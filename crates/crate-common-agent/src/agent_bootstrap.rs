use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;
use core::future::IntoFuture;
use core::pin::Pin;

use log::debug;
use log::error;
use log::info;
use log::warn;

use common_crypto::mesh_generate_mesh_id;
use common_crypto::HmcCertType;
use common_messages::agent_trustee_messages::BootstrapGetKeyPair;
use common_messages::agent_trustee_messages::BootstrapRequest;
use common_messages::agent_trustee_messages::BootstrapResponse;
use common_messages::maintenance_messages::BootstrapComplete;
use common_messages::MeshMessage;
use common_messages::MeshSubsystem;
use common_messages_web::https_listener_messages;
use common_messages_web::websocket_listener_messages;
use common_types::log_error;
use common_types::MeshError;
use common_types::MeshId;
use common_types::MeshStatusType;

use crate::agent::AgentBootstrapData;
use crate::agent::AgentBootstrapState;
use crate::agent::AgentConfigData;
use crate::agent::AgentHandler;

const BOOTSTRAP_RETRY_TIME: i64 = 15000;

/// A `None` that will work in a generic context as a callback argument to
/// bootstrap_with_trustee.
pub const NONE_FN: Option<
    fn(AgentBootstrapData) -> Pin<Box<dyn Future<Output = Result<(), MeshError>> + Sync + Send>>,
> = None;

impl AgentHandler {
    pub fn bootstrap_with_trustee<F, FN>(
        &self,
        need_config: bool,
        bootstrap_get_key_pairs: Option<Vec<BootstrapGetKeyPair>>,
        lookup_uns_records: Option<impl IntoIterator<Item = impl Into<String>>>,
        callback: Option<FN>,
    ) -> Result<Vec<MeshMessage>, MeshError>
    where
        F: Future<Output = Result<(), MeshError>> + Send + Sync + 'static,
        FN: Fn(AgentBootstrapData) -> F + Send + Sync + 'static,
    {
        let bootstrapper = {
            let handler = self.clone();
            let mut state = self.state.write().unwrap();
            let agent_name = state.agent_name.clone();
            let own_id = state.agent_id;
            let agent_trustee_id = state.agent_trustee_id;
            let lookup_uns_records =
                lookup_uns_records.map(|iter| iter.into_iter().map(Into::into).collect());
            state.bootstrap_state = AgentBootstrapState::Started;

            Bootstrapper {
                agent_name,
                own_id,
                agent_trustee_id,
                handler,
                need_config,
                bootstrap_get_key_pairs,
                lookup_uns_records,
                callback,
            }
        };
        Ok(common_async::start_one_task(bootstrapper))
    }
}

struct Bootstrapper<F, FN>
where
    F: Future<Output = Result<(), MeshError>> + Send + Sync,
    FN: Fn(AgentBootstrapData) -> F + Send + Sync,
{
    handler: AgentHandler,
    need_config: bool,
    bootstrap_get_key_pairs: Option<Vec<BootstrapGetKeyPair>>,
    lookup_uns_records: Option<Vec<String>>,
    callback: Option<FN>,
    agent_name: String,
    own_id: MeshId,
    agent_trustee_id: MeshId,
}

impl<F, FN> IntoFuture for Bootstrapper<F, FN>
where
    F: Future<Output = Result<(), MeshError>> + Send + Sync + 'static,
    FN: Fn(AgentBootstrapData) -> F + Send + Sync + 'static,
{
    type Output = Result<(), MeshError>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + Sync>>;
    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.run())
    }
}

impl<F, FN> Bootstrapper<F, FN>
where
    F: Future<Output = Result<(), MeshError>> + Send + Sync,
    FN: Fn(AgentBootstrapData) -> F + Send + Sync,
{
    async fn run(self) -> Result<(), MeshError> {
        info!("start agent bootstrap - now with async!");

        for attempt in 1.. {
            if attempt > 1 {
                common_async::sleep(BOOTSTRAP_RETRY_TIME).await;
                info!("retrying agent bootstrap, attempt {attempt}");
            }

            let Some(bootstrap_response) = self.trustee_bootstrap().await else {
                continue;
            };

            self.handler.set_agent_emid(bootstrap_response.agent_emid);
            let bootstrap_data = AgentBootstrapData {
                config: AgentConfigData {
                    data: bootstrap_response.agent_config,
                },
                uns_records: bootstrap_response.uns_records,
                key_pairs: bootstrap_response.key_pairs,
            };

            if let Some(callback) = &self.callback {
                match callback(bootstrap_data).await {
                    Ok(()) => {
                        info!(
                            "{} agent bootstrap callback returned successfully",
                            self.agent_name
                        );
                    }
                    Err(err) => {
                        error!("{} agent bootstrap callback failed: {err}", self.agent_name);
                        continue;
                    }
                }
            }
            break;
        }
        info!("async agent bootstrap complete!");
        self.handler
            .set_bootstrap_state(AgentBootstrapState::Completed);
        common_async::forward_messages([BootstrapComplete::build_message(self.own_id)]);
        Ok(())
    }

    async fn trustee_bootstrap(&self) -> Option<BootstrapResponse> {
        let message = BootstrapRequest::build_request(
            mesh_generate_mesh_id().unwrap(),
            self.own_id,
            self.agent_trustee_id,
            self.need_config,
            self.agent_name.clone(),
            self.bootstrap_get_key_pairs.clone(),
            self.lookup_uns_records.clone(),
            None,
        )
        .expect("could not build BootstrapRequest");

        let response = match common_async::send_message(message, None).await {
            Ok(response) => response,
            Err(err) => {
                warn!("agent bootstrap request failed: {err}. trying again in 5s..");
                return None;
            }
        };

        if !response.is_success() {
            let status = response
                .header
                .status
                .unwrap_or(MeshStatusType::ServerError);
            error!("BootstrapRequest response failed: {status}");
            None
        } else {
            match response.extract() {
                Ok(bootstrap_response) => Some(bootstrap_response),
                Err(err) => {
                    error!("failed ot deserialize BootstrapResponse: {err}. Trying again in 5s...");
                    None
                }
            }
        }
    }
}

impl AgentHandler {
    pub fn check_purge_expired_tasks(
        &mut self,
        max_to_expire: Option<usize>,
    ) -> (Vec<MeshMessage>, Option<i64>) {
        self.get_requests().check_purge_expired_tasks(max_to_expire)
    }

    fn set_bootstrap_state(&self, bootstrap_state: AgentBootstrapState) {
        self.state.write().unwrap().bootstrap_state = bootstrap_state;
    }

    pub async fn send_certificate_to_listener(
        &self,
        certificate_chain_pem: &str,
        private_key_pem: &str,
    ) -> Result<(), MeshError> {
        debug!("agent sending certificate to listener");
        let (own_id, listener_enclave_id, subsystem) = self.get_listener()?;
        let message = match subsystem {
            Some(MeshSubsystem::HttpsListener) => {
                https_listener_messages::SetCertificateRequest::build_request(
                    mesh_generate_mesh_id().unwrap(),
                    own_id,
                    listener_enclave_id,
                    private_key_pem,
                    certificate_chain_pem,
                    HmcCertType::External,
                    None,
                )?
            }
            Some(MeshSubsystem::WebsocketListener) => {
                websocket_listener_messages::SetCertificateRequest::build_request(
                    mesh_generate_mesh_id().unwrap(),
                    own_id,
                    listener_enclave_id,
                    private_key_pem,
                    certificate_chain_pem,
                    HmcCertType::External,
                    None,
                )?
            }
            invalid => {
                return Err(log_error!(MeshError::BootstrapFailed(format!(
                    "invalid listener: {invalid:?}"
                ))))
            }
        };

        let response = common_async::send_message(message, None).await?;
        if response.is_success() {
            debug!("SetCertificateRequest succeeded!");
            Ok(())
        } else {
            let status = response
                .header
                .status
                .unwrap_or(MeshStatusType::ServerError);
            error!("SetCertificateRequest response failed: {status}");
            Err(MeshError::BootstrapFailed(format!(
                "message error - {status}"
            )))
        }
    }
}
