use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;

use common_agent::agent::AgentHandlerResultData;
use common_agent::agent::AgentHandlerResultDataResponse;
use common_agent::agent::AgentHandlerRoutingRequest;
use common_agent::agent::AgentHandlerRoutingRequestType;
use common_agent::agent::AgentHandlerRoutingResponseType;
use common_agent::agent::DataOperationForEntityResult;
use common_messages::agent_trustee_messages::AgentDataOperationForEntityInput;
use common_messages::message_types::VDRAgentMessageType;
use common_messages_verifiable_credentials::vdr_agent_messages::FetchDIDDocumentRequest;
use common_messages_verifiable_credentials::vdr_agent_messages::FetchDIDDocumentResponse;
use common_types::agent_entity_trustee_objects::DataKey;
use common_types::agent_entity_trustee_objects::DataOperation;
use common_types::log_error;
use common_types::MeshError;
use common_types::MeshStatusType;

use crate::data::DidData;
use crate::VdrAgent;

impl VdrAgent {
    pub(crate) fn handle_fetch_did_document(
        &self,
        request: AgentHandlerRoutingRequest,
    ) -> Result<AgentHandlerResultData, MeshError> {
        let fut = Box::pin(self.clone().run_fetch_did_document(request));
        Ok(AgentHandlerResultData {
            messages: Vec::new(),
            response: AgentHandlerResultDataResponse::Async(fut),
        })
    }

    async fn run_fetch_did_document(
        self,
        request: AgentHandlerRoutingRequest,
    ) -> Result<AgentHandlerRoutingResponseType, MeshError> {
        let context_id = request.context_id;
        let AgentHandlerRoutingRequestType::AgentToAgentEntity(request) = request.request_type
        else {
            return Err(MeshError::NotSupported);
        };
        let FetchDIDDocumentRequest {} = request.message.extract()?;

        let agent_handler = self.0.read().unwrap().agent_handler.clone();
        let DataOperationForEntityResult { result } = agent_handler
            .async_data_operation_for_entity(
                vec![AgentDataOperationForEntityInput {
                    emid: Some(request.emid),
                    emid_operations: vec![DataOperation::Fetch(DataKey {
                        key_path: vec!["DID".into()],
                        ..Default::default()
                    })],
                    ..Default::default()
                }],
                context_id,
            )
            .await?;

        let [ref result] = &*result else {
            return Err(log_error!(MeshError::RequestFailed(format!(
                "expected 1 result, got {}",
                result.len()
            ))));
        };
        let [ref data_entry] = &*result.emid_operations_result else {
            return Err(log_error!(MeshError::RequestFailed(format!(
                "expected 1 entry, got {}",
                result.emid_operations_result.len()
            ))));
        };

        let DidData { did_document, .. } = data_entry
            .data
            .as_ref()
            .ok_or_else(|| MeshError::RequestFailed("DidData entry missing data".into()))
            .and_then(|data| {
                serde_cbor::from_slice(data)
                    .map_err(|e| log_error!(MeshError::ParseError(e.to_string())))
            })?;

        let response_message = request
            .message
            .build_reply(
                VDRAgentMessageType::FetchDIDDocumentResponseType.into(),
                MeshStatusType::Success,
                None,
                FetchDIDDocumentResponse { did_document },
            )
            .unwrap();
        Ok(AgentHandlerRoutingResponseType::AgentToAgentEntity(
            response_message,
        ))
    }
}
