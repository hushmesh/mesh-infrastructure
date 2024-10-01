//! This is the Verifiable Data Registry (VDR) agent.  It is responsible for creating and managing DIDs and
//! their associated DID documents.  It also signs presentations for verifiable credentials.
//! It serves as an example of how to build a mesh agent.   It include storing and fetching data in cell storage,
//! sending requests to HSM agents, and receiving requests from other agents.

#![cfg_attr(feature = "enclave", no_std)]

#[macro_use]
extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use common_agent::agent::AgentBootstrapData;
use common_agent::agent::AgentHandler;
use common_agent::authorization_from_agents;
use common_build_injection::MeshIdentificationData;
use common_messages::enclave::EnclaveFunction;
use common_messages::message_types::VDRAgentMessageType;
use common_messages::MeshMessage;
use common_messages::MeshMessageRef;
use common_messages::MeshSubsystem;
use common_sessions::request_table::RequestTable;
use common_sessions::routing_table::RoutingTable;
use common_sync::RwLock;
use common_types::verifiable_credentials_data_objects::CredentialRepositoryKeyType;
use common_types::MeshError;
use common_types::MeshId;

mod create_did_handler;
mod data;
mod fetch_did_document_handler;
mod link_vdr_handler;
mod sign_presentation_handler;

struct VdrInternal {
    requests: RequestTable,
    routing_table: RoutingTable,
    identification: MeshIdentificationData,
    agent_handler: AgentHandler,
    hsmecdsa_agent_id: Option<MeshId>,
    hsmbbs_agent_id: Option<MeshId>,
    vcholder_agent_id: Option<MeshId>,
    rest_agent_id: Option<MeshId>,
    did_host: Option<String>,
}

#[derive(Clone)]
pub struct VdrAgent(Arc<RwLock<VdrInternal>>);

impl EnclaveFunction for VdrAgent {
    fn process<'c>(
        &mut self,
        message: MeshMessageRef<'c>,
    ) -> Result<(Vec<MeshMessageRef<'c>>, Option<i64>), MeshError> {
        let (routing_table, requests) = {
            let state = self.0.read().unwrap();
            (state.routing_table.clone(), state.requests.clone())
        };
        common_enclave_processor::process(message, routing_table, requests)
    }

    fn get_identification(&self) -> MeshIdentificationData {
        self.0.read().unwrap().identification.clone()
    }

    fn get_init_messages(&self) -> Result<Vec<MeshMessage>, MeshError> {
        let handler = self.clone();
        let agent_handler = self.0.read().unwrap().agent_handler.clone();
        agent_handler.bootstrap_with_trustee(
            false,
            None,
            Some([
                "com.hushmesh.agent-hsmbbs",
                "com.hushmesh.agent-hsmecdsa",
                "com.hushmesh.agent-rest",
                "com.hushmesh.agent-vcholder",
            ]),
            Some(move |data| handler.clone().set_config(data)),
        )
    }

    fn process_timer(&self) -> Result<(Vec<MeshMessage>, Option<i64>), MeshError> {
        let mut agent_handler = self.0.read().unwrap().agent_handler.clone();
        Ok(common_enclave_processor::process_timer_results(|| {
            core::iter::once(agent_handler.check_purge_expired_tasks(None))
        }))
    }
}

impl VdrAgent {
    pub fn new() -> Box<dyn EnclaveFunction> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "test_no_build_data")] {
                static BUILD_STRING: &str = "";
            } else {
                static BUILD_STRING: &str = include_str!(
                    "../../../intermediates/build_data/com.hushmesh.agent-vdr-build-data.json"
                );
            }
        }
        let identification = MeshIdentificationData::load_from_build_string(BUILD_STRING);

        let requests = RequestTable::new();
        let routing_table = RoutingTable::new();

        let agent_trustee_id = identification.parent.as_ref().expect("missing parent").id;

        let agent_handler = AgentHandler::new(
            "VDR".into(),
            identification.own.id,
            agent_trustee_id,
            None,
            None,
            requests.clone(),
            routing_table.clone(),
        );

        Box::new(Self(Arc::new(RwLock::new(VdrInternal {
            requests,
            routing_table,
            identification,
            hsmecdsa_agent_id: None,
            hsmbbs_agent_id: None,
            vcholder_agent_id: None,
            rest_agent_id: None,
            did_host: None,
            agent_handler,
        }))))
    }

    async fn set_config(self, data: AgentBootstrapData) -> Result<(), MeshError> {
        {
            let state = &mut *self.0.write().unwrap();
            let rest_record = data.get_record_by_name_must_exist("com.hushmesh.agent-rest");
            state.rest_agent_id = Some(rest_record.id);
            state.did_host = match &rest_record.route {
                Some(route) => match route.port {
                    443 => Some(route.fqdn.clone()),
                    _ => Some(format!("{}:{}", route.fqdn, route.port)),
                },
                None => {
                    return Err(MeshError::BootstrapFailed(
                        "rest uns record missing route".into(),
                    ))
                }
            };
            state.hsmbbs_agent_id = Some(data.get_agent_id("com.hushmesh.agent-hsmbbs")?);
            state.hsmecdsa_agent_id = Some(data.get_agent_id("com.hushmesh.agent-hsmecdsa")?);
            state.vcholder_agent_id = Some(data.get_agent_id("com.hushmesh.agent-vcholder")?);
        }
        self.register_handlers_post_bootstrap();
        Ok(())
    }

    fn register_handlers_post_bootstrap(&self) {
        let state = self.0.read().unwrap();
        let mut agent_handler = state.agent_handler.clone();
        let vcholder_agent_id = state.vcholder_agent_id.unwrap();
        let rest_agent_id = state.rest_agent_id.unwrap();
        drop(state);

        macro_rules! add_handler {
            ($type:ident, $agent_id:expr, $handler:ident) => {
                let agent = self.clone();
                agent_handler.register_handler_with_authorization_check(
                    MeshSubsystem::VDRAgent,
                    VDRAgentMessageType::$type.into(),
                    authorization_from_agents!([$agent_id]),
                    Box::new(move |message| agent.$handler(message)),
                );
            };
        }

        add_handler!(CreateDIDRequestType, vcholder_agent_id, handle_create_did);
        add_handler!(
            SignPresentationRequestType,
            vcholder_agent_id,
            handle_sign_presentation
        );
        add_handler!(LinkVDRRequestType, rest_agent_id, handle_link_vdr);
        add_handler!(
            FetchDIDDocumentRequestType,
            rest_agent_id,
            handle_fetch_did_document
        );
    }

    pub(crate) fn get_hsm_agent_id(
        &self,
        key_type: CredentialRepositoryKeyType,
    ) -> Result<MeshId, MeshError> {
        let state = self.0.read().unwrap();
        match key_type {
            CredentialRepositoryKeyType::Unknown => Err(MeshError::BadState),
            CredentialRepositoryKeyType::ECDSA => {
                state.hsmecdsa_agent_id.ok_or(MeshError::BadState)
            }
            CredentialRepositoryKeyType::BBS => state.hsmbbs_agent_id.ok_or(MeshError::BadState),
        }
    }
}
