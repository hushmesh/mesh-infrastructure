use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use log::warn;

use common_agent::agent::AgentHandlerResultData;
use common_agent::agent::AgentHandlerResultDataResponse;
use common_agent::agent::AgentHandlerRoutingRequest;
use common_agent::agent::AgentHandlerRoutingRequestType;
use common_agent::agent::AgentHandlerRoutingResponseType;
use common_agent::agent::AgentToAgentLinkEntityResponseData;
use common_crypto::HmcDataType;
use common_crypto::HmcKeyType;
use common_messages::agent_trustee_messages::GetLinkCodesType;
use common_messages::message_types::VDRAgentMessageType;
use common_messages::wrapped_message::WrappedMessage;
use common_messages_verifiable_credentials::hsm_agent_messages::CreateKeyPairRequest;
use common_messages_verifiable_credentials::hsm_agent_messages::CreateKeyPairResponse;
use common_messages_verifiable_credentials::vdr_agent_messages::CreateDIDRequest;
use common_messages_verifiable_credentials::vdr_agent_messages::CreateDIDResponse;
use common_types::agent_entity_trustee_objects::DataEntry;
use common_types::agent_entity_trustee_objects::DataOperation;
use common_types::agent_entity_trustee_objects::LinkRequestId;
use common_types::cbor;
use common_types::log_error;
use common_types::verifiable_credentials_data_objects::CredentialRepositoryKeyType;
use common_types::MeshDataFormat;
use common_types::MeshError;
use common_types::MeshLinkCode;
use common_types::MeshStatusType;
use common_verifiable_credentials::create_did_document;

use crate::data::DidData;
use crate::VdrAgent;

impl VdrAgent {
    pub(crate) fn handle_create_did(
        &self,
        request: AgentHandlerRoutingRequest,
    ) -> Result<AgentHandlerResultData, MeshError> {
        let fut = Box::pin(self.clone().run_create_did(request));
        Ok(AgentHandlerResultData {
            messages: Vec::new(),
            response: AgentHandlerResultDataResponse::Async(fut),
        })
    }

    async fn run_create_did(
        self,
        request: AgentHandlerRoutingRequest,
    ) -> Result<AgentHandlerRoutingResponseType, MeshError> {
        let context_id = request.context_id;
        let AgentHandlerRoutingRequestType::AgentToAgentLinkEntity(request) = request.request_type
        else {
            return Err(MeshError::NotSupported);
        };
        if !request.link_request_id.is_new_id_or_new_id_if_none_exists() {
            return Err(MeshError::RequestFailed(
                "link request id must be new id".into(),
            ));
        }

        let request_message = request
            .message
            .ok_or_else(|| log_error!("request missing message: {}", MeshError::BadState))?;

        if !request.is_new_entity {
            warn!("Requested DID, but one already exists");
            return Ok(AgentHandlerRoutingResponseType::AgentToAgentLinkEntity(
                AgentToAgentLinkEntityResponseData {
                    message: Some(make_create_did_response(&request_message)),
                    ..Default::default()
                },
            ));
        }

        let CreateDIDRequest { key_type } = request_message.extract()?;

        match key_type {
            CredentialRepositoryKeyType::ECDSA => {}
            _ => {
                return Err(MeshError::RequestFailed(
                    "support for {key_type:} not implemented".into(),
                ))
            }
        }

        let agent_handler = self.0.read().unwrap().agent_handler.clone();

        // The private key for the DID is handled by another specialized agent...
        let key_request = CreateKeyPairRequest::build_request(key_type)?;
        let link_response = agent_handler
            .async_link_entity(
                self.get_hsm_agent_id(key_type)?,
                request.emid,
                LinkRequestId::new_id(),
                Some(key_request),
                None,
                context_id,
            )
            .await?;

        let CreateKeyPairResponse { public_key } = link_response
            .reply_message
            .as_ref()
            .ok_or_else(|| MeshError::ParseError("No message in response".into()))?
            .extract()?;

        let (send, reply_callback) = common_async::make_callback_forwarder();
        let msgs = agent_handler.get_link_codes(
            GetLinkCodesType::DirectLinkEmid(request.emid),
            None,
            None,
            None,
            None,
            reply_callback,
            context_id,
        )?;
        let link_code_result = send(msgs).await?;
        let [ref link_code] = &*link_code_result.link_codes else {
            return Err(log_error!(MeshError::RequestFailed(format!(
                "unexpected number of link codes: {}",
                link_code_result.link_codes.len(),
            ))));
        };

        let did_document = create_did_document(
            &self.make_did_url(link_code),
            &public_key,
            HmcKeyType::Ecc384,
            HmcDataType::Der,
        )?;

        let did = did_document.get_id().unwrap().into();
        let did_document = did_document.to_string().map_err(|e| log_error!(e))?.into();

        let did_data = cbor::to_vec_packed(&DidData {
            did,
            did_document,
            key_pair_linked_entity_id: link_response.lemid,
            public_key,
        })
        .unwrap();

        let emid_operations = vec![DataOperation::Insert(DataEntry {
            key_path: vec!["DID".into()],
            data_format: MeshDataFormat::Cbor,
            data: Some(did_data),
            ..Default::default()
        })];

        Ok(AgentHandlerRoutingResponseType::AgentToAgentLinkEntity(
            AgentToAgentLinkEntityResponseData {
                emid_operations: Some(emid_operations),
                message: Some(make_create_did_response(&request_message)),
                ..Default::default()
            },
        ))
    }

    fn make_did_url(&self, code: &MeshLinkCode) -> String {
        let state = self.0.read().unwrap();
        format!(
            "https://{}/did/{}/did.json",
            state.did_host.as_ref().expect("did_host not set"),
            code.as_base64(),
        )
    }
}

fn make_create_did_response(request_message: &WrappedMessage) -> WrappedMessage {
    request_message
        .build_reply(
            VDRAgentMessageType::CreateDIDResponseType.into(),
            MeshStatusType::Success,
            None,
            CreateDIDResponse {},
        )
        .unwrap()
}
