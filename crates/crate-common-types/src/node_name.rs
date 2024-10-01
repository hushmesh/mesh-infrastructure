use alloc::string::String;
#[cfg(not(feature = "enclave"))]
use log::error;
#[cfg(not(feature = "enclave"))]
use std::env;

use common_sync::Mutex;

use crate::MeshError;
use crate::MeshInstanceRoute;
use crate::MeshRoute;

static AGENT_TRUSTEE_NODE_HOST: Mutex<String> = Mutex::new(String::new());
static AGENT_TRUSTEE_NODE_PORT: Mutex<Option<u16>> = Mutex::new(None);

#[cfg(not(feature = "enclave"))]
pub fn get_agent_trustee_node_name() -> Result<String, MeshError> {
    let mut node_name = AGENT_TRUSTEE_NODE_HOST.lock().unwrap();
    if node_name.is_empty() {
        let default_name = match env::var("AGENT_TRUSTEE_NODE_HOST") {
            Ok(name) if !name.is_empty() => name,
            Err(env::VarError::NotPresent) | Ok(_) => match hostname::get() {
                Ok(name) => match name.into_string() {
                    Ok(name) => name,
                    Err(_) => {
                        error!("node name is not set: hostname is invalid");
                        return Err(MeshError::BadState);
                    }
                },
                Err(e) => {
                    error!("node name is not set: hostname::get() failed: {e}");
                    return Err(MeshError::BadState);
                }
            },
            Err(e) => {
                error!("node name is not set: failed to get node name: {e}");
                return Err(MeshError::BadState);
            }
        };
        *node_name = default_name;
    }

    if node_name.is_empty() {
        error!("node name is not set");
        Err(MeshError::BadState)
    } else {
        Ok(node_name.clone())
    }
}

#[cfg(not(feature = "enclave"))]
pub fn get_agent_trustee_node_port() -> Result<Option<u16>, MeshError> {
    let mut node_port = AGENT_TRUSTEE_NODE_PORT.lock().unwrap();
    if node_port.is_none() {
        *node_port = match env::var("AGENT_TRUSTEE_NODE_PORT") {
            Ok(port) => port.parse::<u16>().map(Some).map_err(|e| e.into()),
            Err(env::VarError::NotPresent) => Ok(None),
            Err(e) => Result::<_, Box<dyn std::error::Error>>::Err(e.into()),
        }
        .map_err(|e| MeshError::ParseError(format!("NODE_PORT value is invalid {}", e)))?;
    }
    Ok(*node_port)
}

#[cfg(feature = "enclave")]
pub fn get_agent_trustee_node_name() -> Result<String, MeshError> {
    Ok(AGENT_TRUSTEE_NODE_HOST.lock().unwrap().clone())
}

#[cfg(feature = "enclave")]
pub fn get_agent_trustee_node_port() -> Result<Option<u16>, MeshError> {
    Ok(AGENT_TRUSTEE_NODE_PORT.lock().unwrap().clone())
}

pub fn set_agent_trustee_node_name(node_name: String) {
    let mut global_node_name = AGENT_TRUSTEE_NODE_HOST.lock().unwrap();
    *global_node_name = node_name;
}

pub fn set_agent_trustee_node_port(node_port: Option<u16>) {
    let mut global_node_port = AGENT_TRUSTEE_NODE_PORT.lock().unwrap();
    *global_node_port = node_port;
}

pub fn get_agent_trustee_instance_route(
    route: &Option<MeshRoute>,
) -> Result<MeshInstanceRoute, MeshError> {
    Ok(MeshInstanceRoute {
        fqdn: get_agent_trustee_node_name()?,
        port: get_agent_trustee_node_port()?.unwrap_or(
            route
                .as_ref()
                .ok_or(MeshError::RequestFailed("missing route port".into()))?
                .port,
        ),
    })
}

pub fn is_local_instance_route(
    route: &Option<MeshRoute>,
    instance_route: &MeshInstanceRoute,
) -> Result<bool, MeshError> {
    get_agent_trustee_instance_route(route).map(|local_route| local_route == *instance_route)
}

pub fn get_agent_trustee_node_name_and_port() -> Result<String, MeshError> {
    let node_name = get_agent_trustee_node_name()?;
    let node_port = get_agent_trustee_node_port()?;
    return match node_port {
        Some(port) => Ok(format!("{}:{}", node_name, port)),
        None => Ok(node_name),
    };
}

pub fn set_agent_trustee_node_name_and_port(addr: &str) -> Result<(), MeshError> {
    let (name, port) = match addr.split_once(':') {
        Some((name, port)) => {
            let port = port
                .parse()
                .map_err(|e| MeshError::ParseError(format!("port value is invalid {}", e)))?;
            (name, Some(port))
        }
        None => (addr, None),
    };

    set_agent_trustee_node_name(name.into());
    if port.is_some() {
        set_agent_trustee_node_port(port);
    }
    Ok(())
}
