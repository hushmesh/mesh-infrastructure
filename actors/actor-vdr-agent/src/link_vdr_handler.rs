use common_agent::agent::AgentHandlerResultData;
use common_agent::agent::AgentHandlerResultDataResponse;
use common_agent::agent::AgentHandlerRoutingRequest;
use common_agent::agent::AgentHandlerRoutingRequestType;
use common_agent::agent::AgentHandlerRoutingResponseType;
use common_agent::agent::AgentToAgentLinkEntityResponseData;
use common_messages::message_types::VDRAgentMessageType;
use common_types::agent_entity_trustee_objects::LinkRequestId;
use common_types::MeshError;
use common_types::MeshStatusType;

use crate::VdrAgent;

impl VdrAgent {
    pub(crate) fn handle_link_vdr(
        &self,
        request: AgentHandlerRoutingRequest,
    ) -> Result<AgentHandlerResultData, MeshError> {
        match &request.request_type {
            AgentHandlerRoutingRequestType::AgentToAgentLinkEntity(req) => {
                if !matches!(req.link_request_id, LinkRequestId::LinkCode(_)) {
                    return Err(MeshError::RequestFailed(
                        "link request id must be link code".into(),
                    ));
                }
            }
            _ => return Err(MeshError::NotSupported),
        }
        let response_message = request.get_message_required()?.build_reply_no_payload(
            VDRAgentMessageType::LinkVDRResponseType.into(),
            MeshStatusType::Success,
            None,
        );
        Ok(AgentHandlerResultData {
            messages: vec![],
            response: AgentHandlerResultDataResponse::ImmediateResponse(
                AgentHandlerRoutingResponseType::AgentToAgentLinkEntity(
                    AgentToAgentLinkEntityResponseData {
                        message: Some(response_message),
                        ..Default::default()
                    },
                ),
            ),
        })
    }
}
