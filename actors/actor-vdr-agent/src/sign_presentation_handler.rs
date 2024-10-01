use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::string::ToString;

use common_agent::agent::AgentHandlerResultData;
use common_agent::agent::AgentHandlerResultDataResponse;
use common_agent::agent::AgentHandlerRoutingRequest;
use common_agent::agent::AgentHandlerRoutingRequestType;
use common_agent::agent::AgentHandlerRoutingResponseType;
use common_agent::agent::DataOperationForEntityResult;
use common_agent::agent::SendMessageToLinkedEntityResult;
use common_crypto::HmcHashType;
use common_messages::agent_trustee_messages::AgentDataOperationForEntityInput;
use common_messages::message_types::VDRAgentMessageType;
use common_messages_verifiable_credentials::hsm_agent_messages::BuildProofBytesRequest;
use common_messages_verifiable_credentials::hsm_agent_messages::BuildProofBytesResponse;
use common_messages_verifiable_credentials::vdr_agent_messages::SignPresentationRequest;
use common_messages_verifiable_credentials::vdr_agent_messages::SignPresentationResponse;
use common_types::agent_entity_trustee_objects::DataKey;
use common_types::agent_entity_trustee_objects::DataOperation;
use common_types::log_error;
use common_types::verifiable_credentials_data_objects::CredentialRepositoryKeyType;
use common_types::MeshError;
use common_types::MeshStatusType;
use common_verifiable_credentials::add_holder;
use common_verifiable_credentials::add_proof_value;
use common_verifiable_credentials::ecdsa_hash_document;
use common_verifiable_credentials::multibase_base58btc;
use common_verifiable_credentials::now_rfc3339;
use common_verifiable_credentials::permanent_resident::new_permanent_resident_loader;
use common_verifiable_credentials::DataDocument;
use common_verifiable_credentials::Presentation;
use common_verifiable_credentials::ProofOptions;

use crate::data::DidData;
use crate::VdrAgent;

impl VdrAgent {
    pub(crate) fn handle_sign_presentation(
        &self,
        request: AgentHandlerRoutingRequest,
    ) -> Result<AgentHandlerResultData, MeshError> {
        let fut = Box::pin(self.clone().run_sign_presentation(request));
        Ok(AgentHandlerResultData {
            messages: vec![],
            response: AgentHandlerResultDataResponse::Async(fut),
        })
    }

    async fn run_sign_presentation(
        self,
        request: AgentHandlerRoutingRequest,
    ) -> Result<AgentHandlerRoutingResponseType, MeshError> {
        let context_id = request.context_id;
        let AgentHandlerRoutingRequestType::AgentToAgentEntity(request) = request.request_type
        else {
            return Err(MeshError::NotSupported);
        };

        let sign_req: SignPresentationRequest = request.message.extract()?;

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

        let did_data: DidData = data_entry
            .data
            .as_ref()
            .ok_or_else(|| MeshError::RequestFailed("DidData entry missing data".into()))
            .and_then(|data| {
                serde_cbor::from_slice(data)
                    .map_err(|e| log_error!(MeshError::ParseError(e.to_string())))
            })?;
        let did_doc: DataDocument = did_data.did_document.parse().map_err(|e| {
            MeshError::RequestFailed(format!("Could not parse DidData document: {e}"))
        })?;
        let did_multibase_id = did_doc
            .0
            .pointer("/verificationMethod/0/id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MeshError::RequestFailed("DidData document has no id".into()))?;

        let presentation: DataDocument = sign_req.presentation.parse()?;
        let presentation = add_holder(presentation, did_data.did.into())?;

        let options = ProofOptions(serde_json::json!({
            "type": "DataIntegrityProof",
            "created": now_rfc3339(),
            "cryptosuite": "ecdsa-rdfc-2019",
            "proofPurpose": "authentication",
            "challenge": sign_req.challenge.to_owned(),
            "domain": sign_req.domain.to_owned(),
            "verificationMethod": did_multibase_id,
        }));

        let key_type = CredentialRepositoryKeyType::ECDSA;
        let hash_bytes = common_async::expect_ready(ecdsa_hash_document(
            presentation.clone(),
            options.clone(),
            &mut new_permanent_resident_loader(),
            HmcHashType::Sha384,
        ))
        .expect("ecdsa_hash_document did not finish")?;

        let hsm_lemid = did_data.key_pair_linked_entity_id;

        let proof_req = BuildProofBytesRequest::build_request(key_type, &hash_bytes)?;
        let SendMessageToLinkedEntityResult { reply_message } = agent_handler
            .async_send_message_to_linked_entity(hsm_lemid, proof_req, context_id)
            .await?;
        let BuildProofBytesResponse { proof_bytes } = reply_message.extract_check_status()?;

        let mut proof = options.0;
        proof["proofValue"] = multibase_base58btc(&proof_bytes)?.into();

        let presentation = Presentation(presentation.0);
        let signed_presentation = add_proof_value(presentation, proof)?.to_string()?;

        let response_message = request
            .message
            .build_reply(
                VDRAgentMessageType::SignPresentationResponseType.into(),
                MeshStatusType::Success,
                None,
                SignPresentationResponse {
                    signed_presentation,
                },
            )
            .unwrap();
        Ok(AgentHandlerRoutingResponseType::AgentToAgentEntity(
            response_message,
        ))
    }
}
