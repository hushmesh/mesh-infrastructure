//! This is a compiled application that the Makefile uses to create build data strings.  
//! Build data string are saved to files and then injected into the agent and trustee builds using include_str.

use core::panic;
use std::borrow::Cow;
use std::env;
use std::fs;
use std::num::ParseIntError;
use std::path::Path;
use std::path::PathBuf;

use app_build_data::load_actors_manifest;
use common_build_injection::*;
use common_crypto::mesh_der_to_pem;
use common_crypto::HmcCredType;
use common_types::ConfigOptions;
use common_types::ConnectorType;
use common_types::ListenerType;
use common_types::MeshId;
use common_types::MeshRoute;
use common_types::UnsEntryType;
use predefined_ids::agent_host;
use predefined_ids::agent_port;
use predefined_ids::agent_trustee_host;
use predefined_ids::agent_trustee_port;
use predefined_ids::bootstrap_guardian_port;
use predefined_ids::container_port;
use predefined_ids::get_enclave_file_name;
use predefined_ids::get_predefined_id;
use predefined_ids::guardian_host;
use predefined_ids::guardian_port;
use predefined_ids::trustee_host;
use predefined_ids::trustee_port;

use webpki_root_certs::TLS_SERVER_ROOT_CERTS;

const USE_BOOTSTRAP_GUARDIAN: Option<&str> = core::option_env!("MESH_USE_BOOTSTRAP_GUARDIAN");

fn save_to_file(
    identification: &MeshIdentificationData,
    dir: impl AsRef<Path>,
    filter: Option<&String>,
) -> Result<(), String> {
    let file_name = format!("{}-build-data.json", identification.own.name);
    if matches!(filter, Some(name) if name != &file_name) {
        return Ok(());
    }
    let ref path = dir.as_ref().join(file_name);
    let build_string = identification
        .export_build_string()
        .unwrap_or_else(|err| panic!("failed to export build data {err}"));
    Ok(fs::write(path, build_string)
        .unwrap_or_else(|err| panic!("failed to write {path:?}: {err}")))
}

fn artifact_to_dependency(artifact: &MeshBuildArtifact) -> MeshBuildDependency {
    return MeshBuildDependency {
        id: artifact.id,
        name: artifact.name.clone(),
        artifact_type: artifact.artifact_type,
        fingerprints: vec![],
        enclave_version: "".into(),
        api_version: "".into(),
        route: artifact.route.clone(),
        file_name: artifact.file_name.clone(),
        connector_type: artifact.connector_type,
        listener_type: artifact.listener_type,
        options: artifact.options.clone(),
        not_in_enclave: None,
    };
}

fn artifact_to_dependency_not_in_enclave(artifact: &MeshBuildArtifact) -> MeshBuildDependency {
    return MeshBuildDependency {
        id: artifact.id,
        name: artifact.name.clone(),
        artifact_type: artifact.artifact_type,
        fingerprints: vec![],
        enclave_version: "".into(),
        api_version: "".into(),
        route: artifact.route.clone(),
        file_name: artifact.file_name.clone(),
        connector_type: artifact.connector_type,
        listener_type: artifact.listener_type,
        options: artifact.options.clone(),
        not_in_enclave: Some(true),
    };
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

fn mr_signers_decode(mr_signers: String) -> Vec<Vec<u8>> {
    let split = mr_signers.split('\n');
    let mut components = Vec::new();
    for mr_signer in split {
        let component = decode_hex(mr_signer).unwrap();
        components.push(component);
    }
    return components;
}

fn make_actor_build_string(
    id: MeshId,
    name: impl Into<String>,
    file_name: impl Into<String>,
    external_ca_pem: Cow<'static, str>,
    internal_ca_pem: Option<String>,
    mr_signers: Option<Vec<Vec<u8>>>,
    dependencies: Vec<MeshBuildDependency>,
    needs_http_redirector: Option<bool>,
    parent: Option<MeshBuildDependency>,
    port: u16,
    host: Option<String>,
    container_port: Option<u16>,
) -> MeshIdentificationData {
    let name = name.into();
    let route = host.map(|host| MeshRoute {
        needs_http_redirector: needs_http_redirector.unwrap_or(false),
        fqdn: host,
        port: port,
        container_port,
    });
    MeshIdentificationData {
        own: MeshBuildArtifact {
            name: name.into(),
            id,
            api_versions_supported: vec![],
            route,
            file_name: file_name.into(),
            artifact_type: MeshBuildArtifactType::Actor,
            listener_type: None,
            connector_type: None,
            external_ca_pem,
            internal_ca_pem,
            mr_signers,
            application_version: "".into(),
            enclave_version: "".into(),
            options: ConfigOptions {
                variant_type: 0,
                shutdown: false,
            },
        },
        parent,
        dependencies,
        instance_id: None,
    }
}

fn main() -> Result<(), String> {
    let disable_attestation = match env::var("MESH_BUILD_DISABLE_ATTESTATION").as_deref() {
        Ok("1") => true,
        Ok("0") => false,
        Ok(_) => return Err("MESH_BUILD_DISABLE_ATTESTATION must be 0 or 1".into()),
        Err(_) => {
            return Err(
                "MESH_BUILD_DISABLE_ATTESTATION not set. See README.md for instructions.".into(),
            )
        }
    };
    let disable_internal_tls_verification = match env::var(
        "MESH_BUILD_DISABLE_INTERNAL_TLS_VERIFICATION",
    )
    .as_deref()
    {
        Ok("1") => true,
        Ok("0") => false,
        Ok(_) => return Err("MESH_BUILD_DISABLE_INTERNAL_TLS_VERIFICATION must be 0 or 1".into()),
        Err(_) => {
            return Err("MESH_BUILD_DISABLE_INTERNAL_TLS_VERIFICATION not set. See README.md for instructions.".into());
        }
    };
    let _disable_external_tls_verification = match env::var(
        "MESH_BUILD_DISABLE_LOCALHOST_TLS_VERIFICATION",
    )
    .as_deref()
    {
        Ok("1") => true,
        Ok("0") => false,
        Ok(_) => return Err("MESH_BUILD_DISABLE_LOCALHOST_TLS_VERIFICATION must be 0 or 1".into()),
        Err(_) => {
            return Err("MESH_BUILD_DISABLE_LOCALHOST_TLS_VERIFICATION not set. See README.md for instructions.".into());
        }
    };

    // Optional first argument is a filename filter.
    let filter: Option<String> = env::args_os()
        .nth(1)
        .map(|s| s.to_string_lossy().into_owned());
    let filter = filter.as_ref();

    let ref env: String = match env::var("BUILD_ENV") {
        Ok(val) => val,
        Err(_) => "local".into(),
    };

    let bootstrap_only =
        env::var("MESH_FACTORY_BUILD").map_or(true, |v| v != "1") && env != "local";

    let ref dir: PathBuf = env::var_os("BUILD_DATA_DIR").unwrap_or_default().into();
    let ca_pem_path = dir.join("ca.pem");
    let tls_server_roots = TLS_SERVER_ROOT_CERTS
        .iter()
        .map(|der| {
            mesh_der_to_pem(der, HmcCredType::Cert)
                .unwrap_or_else(|_| panic!("failed to convert der to pem"))
        })
        .map(|pem| {
            String::from_utf8(pem).unwrap_or_else(|_| panic!("failed to convert pem to UTF-8"))
        })
        .collect::<Vec<String>>()
        .join("");
    let external_ca_pem = Cow::from(tls_server_roots);
    let internal_ca_pem = if ca_pem_path.exists() {
        Some(
            std::fs::read_to_string(&ca_pem_path)
                .unwrap_or_else(|err| panic!("failed to read {:?} {}", ca_pem_path, err)),
        )
    } else {
        None
    };
    if !disable_internal_tls_verification && internal_ca_pem.is_none() {
        return Err(
            "BUILD_DATA_DIR/ca.pem is missing and MESH_BUILD_DISABLE_INTERNAL_TLS_VERIFICATION is set to 0".into()
        );
    }
    let mr_signers_path = dir.join("mrsigners.txt");
    let mr_signers = if mr_signers_path.exists() {
        Some(
            std::fs::read_to_string(&mr_signers_path)
                .unwrap_or_else(|err| panic!("failed to read {:?} {}", mr_signers_path, err)),
        )
    } else {
        None
    };
    if !disable_attestation && mr_signers.is_none() {
        return Err(
            "BUILD_DATA_DIR/mrsigners.txt is missing and MESH_BUILD_DISABLE_ATTESTATION is set to 0"
                .into(),
        );
    }
    let mr_signers = mr_signers.map(mr_signers_decode);
    let actors_manifest = load_actors_manifest();

    let ws_listener = MeshIdentificationData {
        own: MeshBuildArtifact {
            name: LISTENER_WEBSOCKET.into(),
            id: get_predefined_id(env, LISTENER_WEBSOCKET),
            api_versions_supported: vec![],
            route: None,
            file_name: get_enclave_file_name(LISTENER_WEBSOCKET),
            artifact_type: MeshBuildArtifactType::Listener,
            listener_type: Some(ListenerType::Tcp),
            connector_type: None,
            external_ca_pem: external_ca_pem.clone(),
            internal_ca_pem: internal_ca_pem.clone(),
            mr_signers: mr_signers.clone(),
            application_version: "".into(),
            enclave_version: "".into(),
            options: ConfigOptions::empty(),
        },
        parent: None,
        dependencies: vec![],
        instance_id: None,
    };
    save_to_file(&ws_listener, dir, filter)?;

    let https_listener = MeshIdentificationData {
        own: MeshBuildArtifact {
            name: LISTENER_HTTPS.into(),
            id: get_predefined_id(env, LISTENER_HTTPS),
            api_versions_supported: vec![],
            route: None,
            file_name: get_enclave_file_name(LISTENER_HTTPS),
            artifact_type: MeshBuildArtifactType::Listener,
            external_ca_pem: external_ca_pem.clone(),
            internal_ca_pem: internal_ca_pem.clone(),
            mr_signers: mr_signers.clone(),
            listener_type: Some(ListenerType::Tcp),
            connector_type: None,
            application_version: "".into(),
            enclave_version: "".into(),
            options: ConfigOptions::empty(),
        },
        parent: None,
        dependencies: vec![],
        instance_id: None,
    };
    save_to_file(&https_listener, dir, filter)?;

    let udp_listener = MeshIdentificationData {
        own: MeshBuildArtifact {
            name: LISTENER_UDP.into(),
            id: get_predefined_id(env, LISTENER_UDP),
            api_versions_supported: vec![],
            route: None,
            file_name: get_enclave_file_name(LISTENER_UDP),
            artifact_type: MeshBuildArtifactType::Listener,
            external_ca_pem: external_ca_pem.clone(),
            internal_ca_pem: internal_ca_pem.clone(),
            mr_signers: mr_signers.clone(),
            listener_type: Some(ListenerType::Udp),
            connector_type: None,
            application_version: "".into(),
            enclave_version: "".into(),
            options: ConfigOptions::empty(),
        },
        parent: None,
        dependencies: vec![],
        instance_id: None,
    };
    save_to_file(&udp_listener, dir, filter)?;

    let ws_connector = MeshIdentificationData {
        own: MeshBuildArtifact {
            name: CONNECTOR_WEBSOCKET.into(),
            id: get_predefined_id(env, CONNECTOR_WEBSOCKET),
            api_versions_supported: vec![],
            route: None,
            file_name: get_enclave_file_name(CONNECTOR_WEBSOCKET),
            artifact_type: MeshBuildArtifactType::Connector,
            listener_type: None,
            connector_type: Some(ConnectorType::Tcp),
            external_ca_pem: external_ca_pem.clone(),
            internal_ca_pem: internal_ca_pem.clone(),
            mr_signers: mr_signers.clone(),
            application_version: "".into(),
            enclave_version: "".into(),
            options: ConfigOptions::empty(),
        },
        parent: None,
        dependencies: vec![],
        instance_id: None,
    };
    save_to_file(&ws_connector, dir, filter)?;

    let filecache_connector = MeshIdentificationData {
        own: MeshBuildArtifact {
            name: CONNECTOR_FILECACHE.into(),
            id: get_predefined_id(env, CONNECTOR_FILECACHE),
            api_versions_supported: vec![],
            route: None,
            file_name: get_enclave_file_name(CONNECTOR_FILECACHE),
            artifact_type: MeshBuildArtifactType::Connector,
            listener_type: None,
            connector_type: Some(ConnectorType::File),
            external_ca_pem: external_ca_pem.clone(),
            internal_ca_pem: internal_ca_pem.clone(),
            mr_signers: mr_signers.clone(),
            application_version: "".into(),
            enclave_version: "".into(),
            options: ConfigOptions::empty(),
        },
        parent: None,
        dependencies: vec![],
        instance_id: None,
    };
    save_to_file(&filecache_connector, dir, filter)?;

    let https_connector = MeshIdentificationData {
        own: MeshBuildArtifact {
            name: CONNECTOR_HTTPS.into(),
            id: get_predefined_id(env, CONNECTOR_HTTPS),
            api_versions_supported: vec![],
            route: None,
            file_name: get_enclave_file_name(CONNECTOR_HTTPS),
            artifact_type: MeshBuildArtifactType::Connector,
            listener_type: None,
            connector_type: Some(ConnectorType::Tcp),
            external_ca_pem: external_ca_pem.clone(),
            internal_ca_pem: internal_ca_pem.clone(),
            mr_signers: mr_signers.clone(),
            application_version: "".into(),
            enclave_version: "".into(),
            options: ConfigOptions::empty(),
        },
        parent: None,
        dependencies: vec![],
        instance_id: None,
    };
    save_to_file(&https_connector, dir, filter)?;

    let database_connector = MeshIdentificationData {
        own: MeshBuildArtifact {
            name: CONNECTOR_DATABASE.into(),
            id: get_predefined_id(env, CONNECTOR_DATABASE),
            api_versions_supported: vec![],
            route: None,
            file_name: get_enclave_file_name(CONNECTOR_DATABASE),
            artifact_type: MeshBuildArtifactType::Connector,
            listener_type: None,
            connector_type: Some(ConnectorType::Database),
            external_ca_pem: external_ca_pem.clone(),
            internal_ca_pem: internal_ca_pem.clone(),
            mr_signers: mr_signers.clone(),
            application_version: "".into(),
            enclave_version: "".into(),
            options: ConfigOptions::empty(),
        },
        parent: None,
        dependencies: vec![],
        instance_id: None,
    };
    save_to_file(&database_connector, dir, filter)?;

    let blobstorage_connector = MeshIdentificationData {
        own: MeshBuildArtifact {
            name: CONNECTOR_BLOBSTORAGE.into(),
            id: get_predefined_id(env, CONNECTOR_BLOBSTORAGE),
            api_versions_supported: vec![],
            route: None,
            file_name: get_enclave_file_name(CONNECTOR_BLOBSTORAGE),
            artifact_type: MeshBuildArtifactType::Connector,
            listener_type: None,
            connector_type: Some(ConnectorType::BlobStorage),
            external_ca_pem: external_ca_pem.clone(),
            internal_ca_pem: internal_ca_pem.clone(),
            mr_signers: mr_signers.clone(),
            application_version: "".into(),
            enclave_version: "".into(),
            options: ConfigOptions::empty(),
        },
        parent: None,
        dependencies: vec![],
        instance_id: None,
    };
    save_to_file(&blobstorage_connector, dir, filter)?;

    let containers_connector = MeshIdentificationData {
        own: MeshBuildArtifact {
            name: CONNECTOR_CONTAINERS.into(),
            id: get_predefined_id(env, CONNECTOR_CONTAINERS),
            api_versions_supported: vec![],
            route: None,
            file_name: "".into(),
            artifact_type: MeshBuildArtifactType::Connector,
            listener_type: None,
            connector_type: Some(ConnectorType::Containers),
            external_ca_pem: external_ca_pem.clone(),
            internal_ca_pem: internal_ca_pem.clone(),
            mr_signers: mr_signers.clone(),
            application_version: "".into(),
            enclave_version: "".into(),
            options: ConfigOptions::empty(),
        },
        parent: None,
        dependencies: vec![],
        instance_id: None,
    };
    save_to_file(&containers_connector, dir, filter)?;

    let bootstrap_guardian = MeshIdentificationData {
        own: MeshBuildArtifact {
            name: ACTOR_GUARDIAN_BOOTSTRAP.into(),
            id: get_predefined_id(env, ACTOR_GUARDIAN_BOOTSTRAP),
            api_versions_supported: vec![],
            route: Some(MeshRoute::new(
                &guardian_host(env),
                bootstrap_guardian_port(env, &actors_manifest),
                Some(container_port(0)),
            )),
            file_name: get_enclave_file_name(ACTOR_GUARDIAN_BOOTSTRAP),
            artifact_type: MeshBuildArtifactType::Actor,
            listener_type: None,
            connector_type: None,
            external_ca_pem: external_ca_pem.clone(),
            internal_ca_pem: internal_ca_pem.clone(),
            mr_signers: mr_signers.clone(),
            application_version: "".into(),
            enclave_version: "".into(),
            options: ConfigOptions {
                variant_type: 1,
                shutdown: false,
            },
        },
        parent: None,
        dependencies: vec![
            artifact_to_dependency(&ws_listener.own),
            artifact_to_dependency(&ws_connector.own),
            artifact_to_dependency(&filecache_connector.own),
        ],
        instance_id: None,
    };
    save_to_file(&bootstrap_guardian, dir, filter)?;

    let guardian_upgrade_producer = MeshIdentificationData {
        own: MeshBuildArtifact {
            name: ACTOR_GUARDIAN_UPGRADE_PRODUCER.into(),
            id: get_predefined_id(env, ACTOR_GUARDIAN_UPGRADE_PRODUCER),
            api_versions_supported: vec![],
            route: None,
            file_name: format!(
                "../data/{}",
                get_enclave_file_name(ACTOR_GUARDIAN_UPGRADE_PRODUCER)
            ),
            artifact_type: MeshBuildArtifactType::Actor,
            listener_type: None,
            connector_type: None,
            external_ca_pem: external_ca_pem.clone(),
            internal_ca_pem: internal_ca_pem.clone(),
            mr_signers: mr_signers.clone(),
            application_version: "".into(),
            enclave_version: "".into(),
            options: ConfigOptions {
                variant_type: 2,
                shutdown: false,
            },
        },
        parent: None,
        dependencies: vec![artifact_to_dependency(&filecache_connector.own)],
        instance_id: None,
    };
    save_to_file(&guardian_upgrade_producer, dir, filter)?;

    let guardian_upgrade_consumer = MeshIdentificationData {
        own: MeshBuildArtifact {
            name: ACTOR_GUARDIAN_UPGRADE_CONSUMER.into(),
            id: get_predefined_id(env, ACTOR_GUARDIAN_UPGRADE_CONSUMER),
            api_versions_supported: vec![],
            route: None,
            file_name: format!(
                "../data/{}",
                get_enclave_file_name(ACTOR_GUARDIAN_UPGRADE_CONSUMER)
            ),
            artifact_type: MeshBuildArtifactType::Actor,
            listener_type: None,
            connector_type: None,
            external_ca_pem: external_ca_pem.clone(),
            internal_ca_pem: internal_ca_pem.clone(),
            mr_signers: mr_signers.clone(),
            application_version: "".into(),
            enclave_version: "".into(),
            options: ConfigOptions {
                variant_type: 3,
                shutdown: true,
            },
        },
        parent: None,
        dependencies: vec![
            artifact_to_dependency(&filecache_connector.own),
            artifact_to_dependency(&guardian_upgrade_producer.own),
        ],
        instance_id: None,
    };
    save_to_file(&guardian_upgrade_consumer, dir, filter)?;

    let facet_guardian = MeshIdentificationData {
        own: MeshBuildArtifact {
            name: ACTOR_GUARDIAN.into(),
            id: get_predefined_id(env, ACTOR_GUARDIAN),
            api_versions_supported: vec![],
            route: Some(MeshRoute::new(
                &guardian_host(env),
                guardian_port(env, &actors_manifest),
                Some(container_port(0)),
            )),
            file_name: get_enclave_file_name(ACTOR_GUARDIAN),
            artifact_type: MeshBuildArtifactType::Actor,
            listener_type: None,
            connector_type: None,
            external_ca_pem: external_ca_pem.clone(),
            internal_ca_pem: internal_ca_pem.clone(),
            mr_signers: mr_signers.clone(),
            application_version: "".into(),
            enclave_version: "".into(),
            options: ConfigOptions {
                variant_type: 0,
                shutdown: false,
            },
        },
        parent: None,
        dependencies: vec![
            artifact_to_dependency(&ws_listener.own),
            artifact_to_dependency(&ws_connector.own),
            artifact_to_dependency(&filecache_connector.own),
        ],
        instance_id: None,
    };
    save_to_file(&facet_guardian, dir, filter)?;

    let dependencies_for_trustee = vec![
        artifact_to_dependency(&ws_listener.own),
        artifact_to_dependency(&ws_connector.own),
        artifact_to_dependency(&database_connector.own),
        artifact_to_dependency(&filecache_connector.own),
    ];

    let global_trustee_parent = match USE_BOOTSTRAP_GUARDIAN {
        Some(_) => artifact_to_dependency(&bootstrap_guardian.own),
        None => artifact_to_dependency(&facet_guardian.own),
    };
    let global_trustee = make_actor_build_string(
        get_predefined_id(env, ACTOR_TRUSTEE_GLOBAL),
        ACTOR_TRUSTEE_GLOBAL,
        get_enclave_file_name(ACTOR_TRUSTEE_GLOBAL),
        external_ca_pem.clone(),
        internal_ca_pem.clone(),
        mr_signers.clone(),
        dependencies_for_trustee.clone(),
        None,
        Some(global_trustee_parent),
        trustee_port(env, ACTOR_TRUSTEE_GLOBAL, &actors_manifest),
        Some(trustee_host(env, ACTOR_TRUSTEE_GLOBAL)),
        Some(container_port(0)),
    );
    save_to_file(&global_trustee, dir, filter)?;

    let mesh_trustee = make_actor_build_string(
        lookup_mesh_id(env, ACTOR_TRUSTEE_MESH),
        ACTOR_TRUSTEE_MESH,
        get_enclave_file_name(ACTOR_TRUSTEE_MESH),
        external_ca_pem.clone(),
        internal_ca_pem.clone(),
        mr_signers.clone(),
        dependencies_for_trustee.clone(),
        None,
        Some(artifact_to_dependency(&global_trustee.own)),
        trustee_port(env, ACTOR_TRUSTEE_MESH, &actors_manifest),
        Some(trustee_host(env, ACTOR_TRUSTEE_MESH)),
        Some(container_port(0)),
    );
    save_to_file(&mesh_trustee, dir, filter)?;
    let root_trustee = make_actor_build_string(
        lookup_mesh_id(env, ACTOR_TRUSTEE_ROOT),
        ACTOR_TRUSTEE_ROOT,
        get_enclave_file_name(ACTOR_TRUSTEE_ROOT),
        external_ca_pem.clone(),
        internal_ca_pem.clone(),
        mr_signers.clone(),
        dependencies_for_trustee.clone(),
        None,
        Some(artifact_to_dependency(&mesh_trustee.own)),
        trustee_port(env, ACTOR_TRUSTEE_ROOT, &actors_manifest),
        Some(trustee_host(env, ACTOR_TRUSTEE_ROOT)),
        Some(container_port(0)),
    );
    save_to_file(&root_trustee, dir, filter)?;
    let intermediate_trustee = make_actor_build_string(
        lookup_mesh_id(env, ACTOR_TRUSTEE_INTERMEDIATE),
        ACTOR_TRUSTEE_INTERMEDIATE,
        get_enclave_file_name(ACTOR_TRUSTEE_INTERMEDIATE),
        external_ca_pem.clone(),
        internal_ca_pem.clone(),
        mr_signers.clone(),
        dependencies_for_trustee.clone(),
        None,
        Some(artifact_to_dependency(&root_trustee.own)),
        trustee_port(env, ACTOR_TRUSTEE_INTERMEDIATE, &actors_manifest),
        Some(trustee_host(env, ACTOR_TRUSTEE_INTERMEDIATE)),
        Some(container_port(0)),
    );
    save_to_file(&intermediate_trustee, dir, filter)?;
    let hushmesh_trustee = make_actor_build_string(
        lookup_mesh_id(env, ACTOR_TRUSTEE_HUSHMESH),
        ACTOR_TRUSTEE_HUSHMESH,
        get_enclave_file_name(ACTOR_TRUSTEE_HUSHMESH),
        external_ca_pem.clone(),
        internal_ca_pem.clone(),
        mr_signers.clone(),
        dependencies_for_trustee.clone(),
        None,
        Some(artifact_to_dependency(&intermediate_trustee.own)),
        trustee_port(env, ACTOR_TRUSTEE_HUSHMESH, &actors_manifest),
        Some(trustee_host(env, ACTOR_TRUSTEE_HUSHMESH)),
        Some(container_port(0)),
    );
    save_to_file(&hushmesh_trustee, dir, filter)?;

    for actor in actors_manifest.actors {
        if actor.uns_entry_type != UnsEntryType::Agent
            || (bootstrap_only && !actor.for_bootstrap.unwrap_or(false))
        {
            continue;
        }
        let actor_agent_name = actor.uns_name;
        let agent_trustee_parent = match actor.parent_uns_name.as_deref() {
            Some("com.hushmesh.trustee-hushmesh") => &hushmesh_trustee.own,
            Some("com.hushmesh.trustee-global") => &global_trustee.own,
            _ => panic!("Unknown parent for agent: {}", actor_agent_name),
        };
        let agent_trustee_parent = Some(artifact_to_dependency(agent_trustee_parent));
        let agent_name_no_prefix = actor_agent_name.strip_prefix(ACTOR_AGENT_BASE).unwrap();
        let agent_trustee_name = format!("{}{}", ACTOR_AGENT_TRUSTEE_BASE, agent_name_no_prefix);
        let entity_trustee_name = format!("{}{}", ACTOR_ENTITY_TRUSTEE_BASE, agent_name_no_prefix);

        let agent_trustee_id = lookup_mesh_id(env, &agent_trustee_name);
        let agent_trustee_file_name = get_enclave_file_name(&agent_trustee_name);
        let agent_trustee = make_actor_build_string(
            agent_trustee_id,
            agent_trustee_name.clone(),
            agent_trustee_file_name,
            external_ca_pem.clone(),
            internal_ca_pem.clone(),
            mr_signers.clone(),
            dependencies_for_trustee.clone(),
            None,
            agent_trustee_parent,
            agent_trustee_port(env, actor.dev_agent_trustee_port),
            Some(agent_trustee_host(env, &agent_trustee_name)),
            Some(container_port(0)),
        );
        let entity_trustee_id = lookup_mesh_id(env, &entity_trustee_name);
        let entity_trustee_file_name = get_enclave_file_name(&entity_trustee_name);
        let entity_trustee = make_actor_build_string(
            entity_trustee_id,
            entity_trustee_name.clone(),
            entity_trustee_file_name,
            external_ca_pem.clone(),
            internal_ca_pem.clone(),
            mr_signers.clone(),
            vec![
                artifact_to_dependency(&database_connector.own),
                artifact_to_dependency(&filecache_connector.own),
            ],
            None,
            Some(artifact_to_dependency(&agent_trustee.own)),
            0,
            None,
            None,
        );
        let mut agent_dependencies = vec![];
        actor
            .dependencies
            .unwrap_or_default()
            .iter()
            .for_each(|dependency| {
                let artifact = match dependency.as_str() {
                    CONNECTOR_BLOBSTORAGE => &blobstorage_connector.own,
                    CONNECTOR_FILECACHE => &filecache_connector.own,
                    CONNECTOR_HTTPS => &https_connector.own,
                    CONNECTOR_WEBSOCKET => &ws_connector.own,
                    LISTENER_HTTPS => &https_listener.own,
                    LISTENER_UDP => &udp_listener.own,
                    LISTENER_WEBSOCKET => &ws_listener.own,
                    CONNECTOR_CONTAINERS => {
                        return agent_dependencies.push(artifact_to_dependency_not_in_enclave(
                            &containers_connector.own,
                        ))
                    }
                    _ => panic!("Unknown dependency: {}", dependency),
                };
                agent_dependencies.push(artifact_to_dependency(artifact));
            });
        let agent_id = lookup_mesh_id(env, &actor_agent_name);
        let agent_file_name = get_enclave_file_name(&actor_agent_name);
        let (ext_agent_host, ext_agent_port) = if actor.has_external_interface.unwrap_or(false) {
            (
                agent_host(env, &actor_agent_name.as_str()),
                agent_port(env, actor.external_interface_port, actor.dev_port),
            )
        } else {
            (None, 0)
        };
        let agent = make_actor_build_string(
            agent_id,
            actor_agent_name.clone(),
            agent_file_name,
            external_ca_pem.clone(),
            internal_ca_pem.clone(),
            mr_signers.clone(),
            agent_dependencies,
            actor.needs_http_redirector,
            Some(artifact_to_dependency(&agent_trustee.own)),
            ext_agent_port,
            ext_agent_host,
            Some(container_port(1)),
        );
        save_to_file(&entity_trustee, dir, filter)?;
        save_to_file(&agent_trustee, dir, filter)?;
        save_to_file(&agent, dir, filter)?;
    }
    let application = MeshIdentificationData {
        own: MeshBuildArtifact {
            name: APPLICATION.into(),
            id: get_predefined_id(env, APPLICATION),
            api_versions_supported: vec![],
            route: None,
            file_name: "".into(),
            artifact_type: MeshBuildArtifactType::Application,
            listener_type: None,
            connector_type: None,
            external_ca_pem: external_ca_pem.clone(),
            internal_ca_pem: internal_ca_pem.clone(),
            mr_signers: mr_signers.clone(),
            application_version: "".into(),
            enclave_version: "".into(),
            options: ConfigOptions::empty(),
        },
        parent: None,
        dependencies: vec![],
        instance_id: None,
    };
    save_to_file(&application, dir, filter)?;

    Ok(())
}

fn lookup_mesh_id(env: &str, name: &str) -> MeshId {
    get_predefined_id(env, name)
}
