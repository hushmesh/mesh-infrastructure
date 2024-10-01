use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use log::error;

use common_crypto::mesh_generate_mesh_id;
use common_messages::agent_messages::AgentMessageType;
use common_messages::agent_messages::AgentToAgentAllEntitiesEntityResult;
use common_messages::agent_messages::AgentToAgentAllEntitiesRequest;
use common_messages::agent_messages::AgentToAgentAllEntitiesResponse;
use common_messages::agent_messages::AgentToAgentCreateTempEntityRequest;
use common_messages::agent_messages::AgentToAgentCreateTempEntityResponse;
use common_messages::agent_messages::AgentToAgentEntityOnNodeInstanceRequest;
use common_messages::agent_messages::AgentToAgentEntityOnNodeInstanceResponse;
use common_messages::agent_messages::AgentToAgentEntityRequest;
use common_messages::agent_messages::AgentToAgentEntityResponse;
use common_messages::agent_messages::AgentToAgentGetLinkCodesRequest;
use common_messages::agent_messages::AgentToAgentGetLinkCodesResponse;
use common_messages::agent_messages::AgentToAgentLinkEntityPostCreateRequest;
use common_messages::agent_messages::AgentToAgentLinkEntityPostCreateResponse;
use common_messages::agent_messages::AgentToAgentLinkEntityPreCreateRequest;
use common_messages::agent_messages::AgentToAgentLinkEntityPreCreateResponse;
use common_messages::agent_messages::AgentToAgentLinkEntityRequest;
use common_messages::agent_messages::AgentToAgentLinkEntityResponse;
use common_messages::agent_messages::AgentToAgentLinkEntityViaDelegateRequest;
use common_messages::agent_messages::AgentToAgentLinkEntityViaDelegateResponse;
use common_messages::agent_messages::AgentToAgentLinkEntityViaDelegateSessionRequest;
use common_messages::agent_messages::AgentToAgentLinkEntityViaDelegateSessionResponse;
use common_messages::agent_messages::AgentToAgentMergeTempEntityRequest;
use common_messages::agent_messages::AgentToAgentMergeTempEntityResponse;
use common_messages::agent_messages::AgentToAgentResponse;
use common_messages::agent_messages::AgentToAgentUnlinkEntitiesRequest;
use common_messages::agent_messages::AgentToAgentUnlinkEntitiesResponse;
use common_messages::agent_messages::TrusteeOrAgentToAgentRequest;
use common_messages::error_to_message_header_status;
use common_messages::wrapped_message::WrappedMessage;
use common_messages::MeshMessage;
use common_messages::MeshMessageType;
use common_messages::MeshSubsystem;
use common_sessions::routing_table::RouterData;
use common_sessions::routing_table::RouterMessageKey;
use common_types::agent_entity_trustee_objects::AgentMeshLinkInfo;
use common_types::cbor::to_vec_packed;
use common_types::log_error;
use common_types::MeshError;
use common_types::MeshId;
use common_types::MeshStatusType;

use crate::agent::AgentHandler;
use crate::agent::AgentHandlerResultData;
use crate::agent::AgentHandlerResultDataResponse;
use crate::agent::AgentHandlerRoutingRequest;
use crate::agent::AgentHandlerRoutingRequestType;
use crate::agent::AgentHandlerRoutingResponseType;
use crate::agent::AgentHandlerRoutingState;
use crate::agent::AgentToAgentAllEntitiesRequestData;
use crate::agent::AgentToAgentCreateTempEntityRequestData;
use crate::agent::AgentToAgentEntityOnNodeInstanceRequestData;
use crate::agent::AgentToAgentEntityPerAllEntitiesRequestData;
use crate::agent::AgentToAgentEntityRequestData;
use crate::agent::AgentToAgentGetLinkCodesRequestData;
use crate::agent::AgentToAgentGetLinkCodesResponseData;
use crate::agent::AgentToAgentLinkEntityPostCreateRequestData;
use crate::agent::AgentToAgentLinkEntityPreCreateRequestData;
use crate::agent::AgentToAgentLinkEntityPreCreateResponseData;
use crate::agent::AgentToAgentLinkEntityRequestData;
use crate::agent::AgentToAgentLinkEntityViaDelegateRequestData;
use crate::agent::AgentToAgentLinkEntityViaDelegateRequestSessionData;
use crate::agent::AgentToAgentLinkEntityViaDelegateResponseData;
use crate::agent::AgentToAgentMergeTempEntityRequestData;
use crate::agent::AgentToAgentUnlinkEntitiesRequestData;
use crate::agent::AgentToAgentUnlinkEntitiesRequestDataEntity;
use crate::agent::AsyncAgentTask;
use crate::authorization_is_connected_either_direction;

macro_rules! authorization_is_owner_default {
    () => {
        Box::new(move |request, link_info| {
            if request.no_default_auth_handler() {
                return Err(MeshError::RequestDenied);
            }
            crate::authorization_handlers::authorization_is_owner_check(
                request,
                link_info,
                common_types::agent_entity_trustee_objects::AgentMeshRelationshipDirection::OriginToSelf,
            )
        })
    };
}

pub type AuthorizationHandler = dyn Fn(&AgentHandlerRoutingRequest, &Option<AgentMeshLinkInfo>) -> Result<(), MeshError>
    + Send
    + Sync;
pub type RequestHandler =
    dyn Fn(AgentHandlerRoutingRequest) -> Result<AgentHandlerResultData, MeshError> + Send + Sync;

impl AgentHandler {
    pub(crate) fn process_agent_to_agent_link_entity_request(
        &self,
        message: MeshMessage,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request: AgentToAgentLinkEntityRequest = message.extract()?;
        let source_agent_id: MeshId = request.requestor_agent_id;
        let request_message = request
            .request_message
            .as_deref()
            .map(WrappedMessage::unserialize)
            .transpose()?;
        let routing_request = AgentHandlerRoutingRequest {
            network_request_id: mesh_generate_mesh_id()?,
            context_id: message.get_context_id(),
            request_type: AgentHandlerRoutingRequestType::AgentToAgentLinkEntity(
                AgentToAgentLinkEntityRequestData {
                    emid: request.emid,
                    entity_type: request.entity_type,
                    lemid_to_be_created: request.lemid_to_be_created,
                    alemid_to_be_created: request.alemid_to_be_created,
                    link_request_id: request.link_request_id,
                    requestor_agent_id: source_agent_id,
                    message: request_message,
                    is_new_entity: request.is_new_entity,
                    link_info: request.link_info,
                    invite_links: request.invite_links,
                    is_link_to_session: request.is_link_to_session,
                    via_external_id_requestor: request.via_external_id_requestor.map(|v| v.into()),
                },
            ),
            source_trusteee_or_agent_id: source_agent_id,
        };
        return self.route_handler_request(
            message,
            routing_request,
            AgentMessageType::AgentToAgentLinkEntityResponseType,
        );
    }

    pub(crate) fn process_agent_to_agent_link_entity_pre_create_request(
        &self,
        message: MeshMessage,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request: AgentToAgentLinkEntityPreCreateRequest = message.extract()?;
        let source_agent_id: MeshId = request.requestor_agent_id;
        let request_message = match request.request_message {
            Some(request_message) => Some(WrappedMessage::unserialize(&request_message)?),
            None => None,
        };
        let routing_request = AgentHandlerRoutingRequest {
            network_request_id: mesh_generate_mesh_id()?,
            context_id: message.get_context_id(),
            request_type: AgentHandlerRoutingRequestType::AgentToAgentLinkEntityPreCreate(
                AgentToAgentLinkEntityPreCreateRequestData {
                    entity_type: request.entity_type,
                    link_request_id: request.link_request_id,
                    requestor_agent_id: source_agent_id,
                    message: request_message,
                    is_new_entity: request.is_new_entity,
                    link_info: request.link_info,
                    alemid_to_be_created: request.alemid_to_be_created,
                    is_link_to_session: request.is_link_to_session,
                    via_external_id_requestor: request.via_external_id_requestor.map(|v| v.into()),
                },
            ),
            source_trusteee_or_agent_id: source_agent_id,
        };
        return self.route_handler_request(
            message,
            routing_request,
            AgentMessageType::AgentToAgentLinkEntityPreCreateResponseType,
        );
    }

    pub(crate) fn process_agent_to_agent_link_entity_post_create_request(
        &self,
        message: MeshMessage,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request: AgentToAgentLinkEntityPostCreateRequest = message.extract()?;
        let source_agent_id: MeshId = request.requestor_agent_id;
        let routing_request = AgentHandlerRoutingRequest {
            network_request_id: mesh_generate_mesh_id()?,
            context_id: message.get_context_id(),
            request_type: AgentHandlerRoutingRequestType::AgentToAgentLinkEntityPostCreate(
                AgentToAgentLinkEntityPostCreateRequestData {
                    emid: request.emid,
                    lemid: request.lemid,
                    alemid: request.alemid,
                    link_info: request.link_info,
                    requestor_agent_id: request.requestor_agent_id,
                    is_new_entity: request.is_new_entity,
                },
            ),
            source_trusteee_or_agent_id: source_agent_id,
        };
        return self.route_handler_request(
            message,
            routing_request,
            AgentMessageType::AgentToAgentLinkEntityPostCreateResponseType,
        );
    }

    pub(crate) fn process_agent_to_agent_link_entity_via_delegate_request(
        &self,
        message: MeshMessage,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request: AgentToAgentLinkEntityViaDelegateRequest = message.extract()?;
        let source_agent_id = request.requestor_agent_id;
        let request_message = match request.request_message {
            Some(request_message) => Some(WrappedMessage::unserialize(&request_message)?),
            None => None,
        };
        let routing_request = AgentHandlerRoutingRequest {
            network_request_id: mesh_generate_mesh_id()?,
            context_id: message.get_context_id(),
            request_type: AgentHandlerRoutingRequestType::AgentToAgentLinkEntityViaDelegate(
                AgentToAgentLinkEntityViaDelegateRequestData {
                    emid: request.emid.into(),
                    requestor_lemid_to_be_created: request.requestor_lemid_to_be_created,
                    requestor_alemid_to_be_created: request.requestor_lemid_to_be_created,
                    requestor_agent_id: source_agent_id,
                    requestor_link_info: request.requestor_link_info,
                    delegate_link_info: request.delegate_link_info,
                    message: request_message,
                    delegate_lemid: request.delegate_lemid,
                    is_link_to_session: request.is_link_to_session,
                    entity_type: request.entity_type,
                },
            ),
            source_trusteee_or_agent_id: source_agent_id,
        };
        return self.route_handler_request(
            message,
            routing_request,
            AgentMessageType::AgentToAgentLinkEntityViaDelegateResponseType,
        );
    }

    pub(crate) fn process_agent_to_agent_link_entity_via_delegate_session_request(
        &self,
        message: MeshMessage,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request: AgentToAgentLinkEntityViaDelegateSessionRequest = message.extract()?;
        let source_agent_id = request.requestor_agent_id;
        let request_message = match request.request_message {
            Some(request_message) => Some(WrappedMessage::unserialize(&request_message)?),
            None => None,
        };
        let routing_request = AgentHandlerRoutingRequest {
            network_request_id: mesh_generate_mesh_id()?,
            context_id: message.get_context_id(),
            request_type: AgentHandlerRoutingRequestType::AgentToAgentLinkEntityViaDelegateSession(
                AgentToAgentLinkEntityViaDelegateRequestSessionData {
                    emid: request.emid,
                    requestor_lemid: request.requestor_lemid,
                    requestor_alemid: request.requestor_alemid,
                    requestor_agent_id: request.requestor_agent_id,
                    target_lemid: request.target_lemid,
                    target_alemid: request.target_alemid,
                    target_agent_id: request.target_agent_id,
                    message: request_message,
                    requestor_link_info: request.requestor_link_info,
                    delegate_link_info: request.delegate_link_info,
                    delegate_lemid: request.delegate_lemid,
                    delegate_alemid: request.delegate_alemid,
                    delegate_agent_id: request.delegate_agent_id,
                },
            ),
            source_trusteee_or_agent_id: source_agent_id,
        };
        return self.route_handler_request(
            message,
            routing_request,
            AgentMessageType::AgentToAgentLinkEntityViaDelegateSessionResponseType,
        );
    }

    pub(crate) fn process_agent_to_agent_get_link_codes_request(
        &self,
        message: MeshMessage,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request: AgentToAgentGetLinkCodesRequest = message.extract()?;
        let source_agent_id = request.requestor_agent_id;
        let request_message = match request.request_message {
            Some(request_message) => Some(WrappedMessage::unserialize(&request_message)?),
            None => None,
        };
        let routing_request = AgentHandlerRoutingRequest {
            network_request_id: mesh_generate_mesh_id()?,
            context_id: message.get_context_id(),
            request_type: AgentHandlerRoutingRequestType::AgentToAgentGetLinkCodes(
                AgentToAgentGetLinkCodesRequestData {
                    emid: request.emid,
                    lemid: request.lemid,
                    message: request_message,
                    link_info: request.link_info,
                    via_external_id_requestor: request.via_external_id_requestor.map(|v| v.into()),
                    human_proxy_agent_id: request.human_proxy_agent_id,
                },
            ),
            source_trusteee_or_agent_id: source_agent_id,
        };
        return self.route_handler_request(
            message,
            routing_request,
            AgentMessageType::AgentToAgentGetLinkCodesResponseType,
        );
    }

    pub(crate) fn process_agent_to_agent_create_temp_entity_request(
        &self,
        message: MeshMessage,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request: AgentToAgentCreateTempEntityRequest = message.extract()?;
        let source_agent_id = request.requestor_agent_id;
        let request_message = match request.request_message {
            Some(request_message) => Some(WrappedMessage::unserialize(&request_message)?),
            None => None,
        };
        let routing_request = AgentHandlerRoutingRequest {
            network_request_id: mesh_generate_mesh_id()?,
            context_id: message.get_context_id(),
            request_type: AgentHandlerRoutingRequestType::AgentToAgentCreateTempEntity(
                AgentToAgentCreateTempEntityRequestData {
                    emid: request.emid,
                    message: request_message,
                    entity_type: request.entity_type,
                    requestor_agent_id: request.requestor_agent_id,
                    is_new_entity: request.is_new_entity,
                    via_external_id_requestor: request.via_external_id_requestor.map(|v| v.into()),
                    external_id: request.external_id,
                    human_proxy_agent_id: request.human_proxy_agent_id,
                },
            ),
            source_trusteee_or_agent_id: source_agent_id,
        };
        return self.route_handler_request(
            message,
            routing_request,
            AgentMessageType::AgentToAgentCreateTempEntityResponseType,
        );
    }

    pub(crate) fn process_agent_to_agent_merge_temp_entity_request(
        &self,
        message: MeshMessage,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request: AgentToAgentMergeTempEntityRequest = message.extract()?;
        let source_agent_id = request.requestor_agent_id;
        let routing_request = AgentHandlerRoutingRequest {
            network_request_id: mesh_generate_mesh_id()?,
            context_id: message.get_context_id(),
            request_type: AgentHandlerRoutingRequestType::AgentToAgentMergeTempEntity(
                AgentToAgentMergeTempEntityRequestData {
                    emid: request.emid,
                    merge_emids: request.merge_emids,
                },
            ),
            source_trusteee_or_agent_id: source_agent_id,
        };
        return self.route_handler_request(
            message,
            routing_request,
            AgentMessageType::AgentToAgentMergeTempEntityResponseType,
        );
    }

    pub(crate) fn process_agent_to_agent_unlink_entities_request(
        &self,
        message: MeshMessage,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request: AgentToAgentUnlinkEntitiesRequest = message.extract()?;
        let mut entities: Vec<AgentToAgentUnlinkEntitiesRequestDataEntity> = vec![];
        for entity in request.entities.into_iter() {
            entities.push(AgentToAgentUnlinkEntitiesRequestDataEntity {
                lemid: entity.lemid.into(),
                alemid: entity.alemid.into(),
                emid: entity.emid.into(),
                link_info: entity.link_info,
            });
        }
        let source_agent_id = request.requestor_agent_id;
        let routing_request = AgentHandlerRoutingRequest {
            network_request_id: mesh_generate_mesh_id()?,
            context_id: message.get_context_id(),
            request_type: AgentHandlerRoutingRequestType::AgentToAgentUnlinkEntities(
                AgentToAgentUnlinkEntitiesRequestData {
                    requestor_agent_id: source_agent_id,
                    entities,
                },
            ),
            source_trusteee_or_agent_id: source_agent_id,
        };
        return self.route_handler_request(
            message,
            routing_request,
            AgentMessageType::AgentToAgentUnlinkEntitiesResponseType,
        );
    }

    pub(crate) fn process_agent_to_agent_entity_request(
        &self,
        message: MeshMessage,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request: AgentToAgentEntityRequest = message.extract()?;
        let source_agent_id = request.requestor_agent_id;
        let request_message = WrappedMessage::unserialize(&request.request_message)?;
        let routing_request = AgentHandlerRoutingRequest {
            network_request_id: mesh_generate_mesh_id()?,
            context_id: message.get_context_id(),
            source_trusteee_or_agent_id: source_agent_id,
            request_type: AgentHandlerRoutingRequestType::AgentToAgentEntity(
                AgentToAgentEntityRequestData {
                    lemid: request.lemid.into(),
                    alemid: request.alemid.into(),
                    emid: request.emid.into(),
                    message: request_message,
                    link_info: request.link_info,
                },
            ),
        };
        return self.route_handler_request(
            message,
            routing_request,
            AgentMessageType::AgentToAgentEntityResponseType,
        );
    }

    pub(crate) fn process_agent_to_agent_entity_on_node_instance_request(
        &self,
        message: MeshMessage,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request: AgentToAgentEntityOnNodeInstanceRequest = message.extract()?;
        let request_message = WrappedMessage::unserialize(&request.request_message)?;
        let routing_request = AgentHandlerRoutingRequest {
            network_request_id: mesh_generate_mesh_id()?,
            context_id: message.get_context_id(),
            source_trusteee_or_agent_id: self.get_agent_id(),
            request_type: AgentHandlerRoutingRequestType::AgentToAgentEntityOnNodeInstance(
                AgentToAgentEntityOnNodeInstanceRequestData {
                    emid: request.emid.into(),
                    message: request_message,
                },
            ),
        };
        return self.route_handler_request(
            message,
            routing_request,
            AgentMessageType::AgentToAgentEntityOnNodeInstanceResponseType,
        );
    }

    pub(crate) fn process_agent_to_agent_all_entities_request(
        &self,
        message: MeshMessage,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request: AgentToAgentAllEntitiesRequest = message.extract()?;
        let source_agent_id = request.requestor_agent_id;
        let request_message = WrappedMessage::unserialize(&request.request_message)?;
        let mut entities: Vec<AgentToAgentEntityPerAllEntitiesRequestData> = vec![];
        for request_entity in request.entities.into_iter() {
            entities.push(AgentToAgentEntityPerAllEntitiesRequestData {
                lemid: request_entity.lemid.into(),
                alemid: request_entity.alemid.into(),
                emid: request_entity.emid.into(),
                link_info: request_entity.link_info,
            });
        }
        let routing_request = AgentHandlerRoutingRequest {
            network_request_id: mesh_generate_mesh_id()?,
            context_id: message.get_context_id(),
            source_trusteee_or_agent_id: source_agent_id,
            request_type: AgentHandlerRoutingRequestType::AgentToAgentAllEntities(
                AgentToAgentAllEntitiesRequestData {
                    entities,
                    message: request_message,
                },
            ),
        };
        return self.route_handler_request(
            message,
            routing_request,
            AgentMessageType::AgentToAgentAllEntitiesResponseType,
        );
    }

    pub(crate) fn process_trustee_or_agent_to_agent_request(
        &self,
        message: MeshMessage,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request: TrusteeOrAgentToAgentRequest = message.extract()?;
        let source_id = request
            .requestor_agent_id
            .unwrap_or(request.requestor_trustee_id);
        let request_message = WrappedMessage::unserialize(&request.request_message)?;
        let routing_request = AgentHandlerRoutingRequest {
            network_request_id: mesh_generate_mesh_id()?,
            context_id: message.get_context_id(),
            request_type: AgentHandlerRoutingRequestType::TrusteeOrAgentToAgent(request_message),
            source_trusteee_or_agent_id: source_id,
        };
        return self.route_handler_request(
            message,
            routing_request,
            AgentMessageType::TrusteeOrAgentToAgentResponseType,
        );
    }

    fn route_handler_request(
        &self,
        message: MeshMessage,
        request: AgentHandlerRoutingRequest,
        response_message_type: AgentMessageType,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        match self.route_handler_request_check_err(
            message.clone(),
            request.clone(),
            response_message_type,
        ) {
            Ok(messages) => Ok(messages),
            Err(err) => {
                error!(
                    "request {} failed: {} - {:?} {} : {:?}",
                    request.request_type,
                    err,
                    request
                        .get_message_subsystem()
                        .unwrap_or(message.header.subsystem),
                    request
                        .get_message_type()
                        .unwrap_or(message.header.message_type),
                    request.get_link_info(),
                );
                self.send_agent_response(AgentHandlerRoutingState {
                    message,
                    reply_data: None,
                    reply_error: Some(err),
                    response_message_type,
                    reply_status: None,
                    reply_status_message: None,
                    request_type: request.request_type,
                })
            }
        }
    }

    fn route_handler_request_check_err(
        &self,
        message: MeshMessage,
        request: AgentHandlerRoutingRequest,
        response_message_type: AgentMessageType,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let state_id = request.network_request_id;
        let agent_message = request.get_message();
        let route = {
            let state = self.state.read().unwrap();

            let route_option = agent_message.and_then(|message| {
                state
                    .handler_routing_table
                    .find_message_route(&RouterMessageKey::new(
                        message.subsystem,
                        message.message_type,
                    ))
            });
            match route_option {
                Some(route) => route,
                None => match request.request_type {
                    AgentHandlerRoutingRequestType::AgentToAgentLinkEntityViaDelegate(_) => {
                        state.default_handle_link_via_delegate_route.clone()
                    }
                    AgentHandlerRoutingRequestType::AgentToAgentLinkEntityViaDelegateSession(_) => {
                        state.default_handle_link_via_delegate_session_route.clone()
                    }
                    AgentHandlerRoutingRequestType::AgentToAgentGetLinkCodes(_) => {
                        state.default_handle_get_link_codes_route.clone()
                    }
                    AgentHandlerRoutingRequestType::AgentToAgentCreateTempEntity(_) => {
                        state.default_handle_create_temp_entity_route.clone()
                    }
                    AgentHandlerRoutingRequestType::AgentToAgentMergeTempEntity(_) => {
                        state.default_handle_merge_temp_entity_route.clone()
                    }
                    AgentHandlerRoutingRequestType::AgentToAgentLinkEntity(_) => {
                        state.default_handle_link_entity_route.clone()
                    }
                    AgentHandlerRoutingRequestType::AgentToAgentLinkEntityPostCreate(_) => {
                        state.default_handle_link_entity_post_create_route.clone()
                    }
                    AgentHandlerRoutingRequestType::AgentToAgentLinkEntityPreCreate(_) => {
                        state.default_handle_link_entity_pre_create_route.clone()
                    }
                    AgentHandlerRoutingRequestType::AgentToAgentUnlinkEntities(_) => {
                        if state.default_handle_unlink_entities_route.is_none() {
                            let state = AgentHandlerRoutingState {
                                message,
                                reply_data: Some(
                                    AgentHandlerRoutingResponseType::AgentToAgentUnlinkEntities(),
                                ),
                                response_message_type,
                                reply_error: None,
                                reply_status: Some(MeshStatusType::Success),
                                reply_status_message: None,
                                request_type: request.request_type,
                            };
                            return self.send_agent_response(state);
                        }
                        state.default_handle_unlink_entities_route.clone()
                    }
                    _ => None,
                }
                .ok_or_else(|| {
                    log_error!(MeshError::RequestFailed("no route to agent found".into()))
                })?,
            }
        };
        let request_type = request.request_type.clone();
        let result_data = (route.router_callback)(request)?;

        let state = AgentHandlerRoutingState {
            message,
            reply_data: None,
            response_message_type,
            reply_error: None,
            reply_status: None,
            reply_status_message: None,
            request_type,
        };
        self.add_pending_state(state_id, state);
        match result_data.response {
            AgentHandlerResultDataResponse::ImmediateResponse(reply) => {
                let mut state = self.get_pending_state(state_id).unwrap();
                state.reply_data = Some(reply);
                Ok([result_data.messages, self.send_agent_response(state)?].concat())
            }
            AgentHandlerResultDataResponse::EventualResponse => Ok(result_data.messages),
            AgentHandlerResultDataResponse::Async(fut) => {
                self.run_async_responder(state_id, fut);
                Ok(result_data.messages)
            }
        }
    }

    // Long term, I'm sure we'll want to do something more specialized to handle async agent
    // handlers. But, in the meantime, AgentHandlerResultDataResponse::Async provides a simple way
    // to write an async handler that uses the existing system.
    fn run_async_responder(&self, state_id: MeshId, fut: AsyncAgentTask) {
        let handler = self.clone();
        common_async::spawn_task(async move {
            let reply_result = match fut.await {
                Ok(reply_data) => handler.send_reply_for_handler(state_id, reply_data),
                Err(err) => handler.send_error_for_handler(state_id, err),
            };
            match reply_result {
                Ok(msgs) => common_async::forward_messages(msgs),
                Err(err) => error!("failed to send reponse: {err}"),
            }
            Ok(())
        });
    }

    fn send_agent_response(
        &self,
        state: AgentHandlerRoutingState,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        if let Some(err) = state.reply_error {
            let (status, status_message) = error_to_message_header_status(&err, None);
            let outer_reply = state.message.build_reply(
                state.response_message_type.into(),
                status,
                Some(status_message),
                None,
            );
            return Ok(vec![outer_reply]);
        }

        if let Some(reply_status) = state.reply_status {
            let outer_reply = state.message.build_reply(
                state.response_message_type.into(),
                reply_status,
                state.reply_status_message,
                None,
            );
            return Ok(vec![outer_reply]);
        }
        let reply_data = state
            .reply_data
            .ok_or_else(|| log_error!(MeshError::BadState))?;
        let outer_reply_payload: Vec<u8> = match state.response_message_type {
            AgentMessageType::AgentToAgentEntityResponseType => {
                match state.request_type {
                    AgentHandlerRoutingRequestType::AgentToAgentEntity(_) => {}
                    _ => {
                        return Err(log_error!(MeshError::BadState));
                    }
                }

                let reply_message = match reply_data {
                    AgentHandlerRoutingResponseType::AgentToAgentEntity(message) => message,
                    _ => return Err(log_error!(MeshError::BadState)),
                };
                let response_message = reply_message.serialize()?;
                let response = AgentToAgentEntityResponse {
                    response_message: response_message,
                };
                to_vec_packed(&response).map_err(|e| log_error!(e))?
            }
            AgentMessageType::AgentToAgentEntityOnNodeInstanceResponseType => {
                match state.request_type {
                    AgentHandlerRoutingRequestType::AgentToAgentEntityOnNodeInstance(_) => {}
                    _ => {
                        return Err(log_error!(MeshError::BadState));
                    }
                }

                let reply_message = match reply_data {
                    AgentHandlerRoutingResponseType::AgentToAgentEntityOnNodeInstance(message) => {
                        message
                    }
                    _ => return Err(log_error!(MeshError::BadState)),
                };
                let response_message = reply_message.serialize()?;
                let response = AgentToAgentEntityOnNodeInstanceResponse {
                    response_message: response_message,
                };
                to_vec_packed(&response).map_err(|e| log_error!(e))?
            }
            AgentMessageType::TrusteeOrAgentToAgentResponseType => {
                match state.request_type {
                    AgentHandlerRoutingRequestType::TrusteeOrAgentToAgent(_) => {}
                    _ => {
                        return Err(log_error!(MeshError::BadState));
                    }
                }
                let reply_message = match reply_data {
                    AgentHandlerRoutingResponseType::TrusteeOrAgentToAgent(message) => message,
                    _ => return Err(log_error!(MeshError::BadState)),
                };
                let response_message = reply_message.serialize()?;
                let response = AgentToAgentResponse { response_message };
                to_vec_packed(&response).map_err(|e| log_error!(e))?
            }
            AgentMessageType::AgentToAgentAllEntitiesResponseType => {
                match state.request_type {
                    AgentHandlerRoutingRequestType::AgentToAgentAllEntities(_) => {}
                    _ => {
                        return Err(log_error!(MeshError::BadState));
                    }
                }
                let responses = match reply_data {
                    AgentHandlerRoutingResponseType::AgentToAgentAllEntities(mut response) => {
                        let mut entities: Vec<AgentToAgentAllEntitiesEntityResult> = vec![];
                        for response_entity in response.responses.iter_mut() {
                            let entity = AgentToAgentAllEntitiesEntityResult {
                                emid: response_entity.emid.into(),
                                lemid: response_entity.lemid.into(),
                                response_message: response_entity.response_message.serialize()?,
                            };
                            entities.push(entity);
                        }
                        entities
                    }
                    _ => return Err(log_error!(MeshError::BadState)),
                };
                let response = AgentToAgentAllEntitiesResponse { responses };
                to_vec_packed(&response).map_err(|e| log_error!(e))?
            }
            AgentMessageType::AgentToAgentLinkEntityPostCreateResponseType => {
                match state.request_type {
                    AgentHandlerRoutingRequestType::AgentToAgentLinkEntityPostCreate(_) => {}
                    _ => {
                        return Err(log_error!(MeshError::BadState));
                    }
                }
                let response = AgentToAgentLinkEntityPostCreateResponse {};
                to_vec_packed(&response).map_err(|e| log_error!(e))?
            }
            AgentMessageType::AgentToAgentLinkEntityPreCreateResponseType => {
                match state.request_type {
                    AgentHandlerRoutingRequestType::AgentToAgentLinkEntityPreCreate(_) => {}
                    _ => {
                        return Err(log_error!(MeshError::BadState));
                    }
                }
                let data = match reply_data {
                    AgentHandlerRoutingResponseType::AgentToAgentLinkEntityPreCreate(data) => data,
                    _ => return Err(log_error!(MeshError::BadState)),
                };
                let response = AgentToAgentLinkEntityPreCreateResponse {
                    link_updates: data.link_updates,
                };
                to_vec_packed(&response).map_err(|e| log_error!(e))?
            }
            AgentMessageType::AgentToAgentLinkEntityResponseType => {
                match state.request_type {
                    AgentHandlerRoutingRequestType::AgentToAgentLinkEntity(_) => {}
                    _ => {
                        return Err(log_error!(MeshError::BadState));
                    }
                }
                let data = match reply_data {
                    AgentHandlerRoutingResponseType::AgentToAgentLinkEntity(data) => data,
                    _ => return Err(log_error!(MeshError::BadState)),
                };
                let response_message = match data.message {
                    Some(reply_message) => Some(reply_message.serialize()?),
                    None => None,
                };
                let response = AgentToAgentLinkEntityResponse {
                    link_updates: data.link_updates,
                    expiration_time: data.expiration_time,
                    emid_operations: data.emid_operations,
                    agent_emid_operations: data.agent_emid_operations,
                    lemid_operations: data.lemid_operations,
                    invite_lemid_operations: data.invite_lemid_operations,
                    response_message,
                };
                to_vec_packed(&response).map_err(|e| log_error!(e))?
            }
            AgentMessageType::AgentToAgentLinkEntityViaDelegateResponseType => {
                match state.request_type {
                    AgentHandlerRoutingRequestType::AgentToAgentLinkEntityViaDelegate(_) => {}
                    _ => {
                        return Err(log_error!(MeshError::BadState));
                    }
                }
                let data = match reply_data {
                    AgentHandlerRoutingResponseType::AgentToAgentLinkEntityViaDelegate(data) => {
                        data
                    }
                    _ => return Err(log_error!(MeshError::BadState)),
                };
                let response_message = match data.message {
                    Some(reply_message) => Some(reply_message.serialize()?),
                    None => None,
                };
                let response = AgentToAgentLinkEntityViaDelegateResponse {
                    emid_operations: data.emid_operations,
                    lemid_operations: data.lemid_operations,
                    response_message,
                    link_updates: data.link_updates,
                };
                to_vec_packed(&response).map_err(|e| log_error!(e))?
            }
            AgentMessageType::AgentToAgentLinkEntityViaDelegateSessionResponseType => {
                match state.request_type {
                    AgentHandlerRoutingRequestType::AgentToAgentLinkEntityViaDelegateSession(_) => {
                    }
                    _ => {
                        return Err(log_error!(MeshError::BadState));
                    }
                }
                let data = match reply_data {
                    AgentHandlerRoutingResponseType::AgentToAgentLinkEntityViaDelegateSession(
                        data,
                    ) => data,
                    _ => return Err(log_error!(MeshError::BadState)),
                };
                let response_message = match data.message {
                    Some(reply_message) => Some(reply_message.serialize()?),
                    None => None,
                };
                let response = AgentToAgentLinkEntityViaDelegateSessionResponse {
                    emid_operations: data.emid_operations,
                    lemid_operations: data.lemid_operations,
                    response_message,
                    link_updates: data.link_updates,
                };
                to_vec_packed(&response).map_err(|e| log_error!(e))?
            }
            AgentMessageType::AgentToAgentGetLinkCodesResponseType => {
                match state.request_type {
                    AgentHandlerRoutingRequestType::AgentToAgentGetLinkCodes(_) => {}
                    _ => {
                        return Err(log_error!(MeshError::BadState));
                    }
                }
                let (reply_message, human_proxy_agent_link_code) = match reply_data {
                    AgentHandlerRoutingResponseType::AgentToAgentGetLinkCodes(data) => {
                        (data.message, data.human_proxy_agent_link_code)
                    }
                    _ => return Err(log_error!(MeshError::BadState)),
                };
                let response_message = match reply_message {
                    Some(reply_message) => Some(reply_message.serialize()?),
                    None => None,
                };
                let response = AgentToAgentGetLinkCodesResponse {
                    response_message,
                    human_proxy_agent_link_code,
                };
                to_vec_packed(&response).map_err(|e| log_error!(e))?
            }
            AgentMessageType::AgentToAgentCreateTempEntityResponseType => {
                match state.request_type {
                    AgentHandlerRoutingRequestType::AgentToAgentCreateTempEntity(_) => {}
                    _ => {
                        return Err(log_error!(MeshError::BadState));
                    }
                }
                let data = match reply_data {
                    AgentHandlerRoutingResponseType::AgentToAgentCreateTempEntity(data) => data,
                    _ => return Err(log_error!(MeshError::BadState)),
                };
                let response_message = match data.message {
                    Some(reply_message) => Some(reply_message.serialize()?),
                    None => None,
                };
                let response = AgentToAgentCreateTempEntityResponse {
                    response_message,
                    emid_operations: data.emid_operations,
                    human_proxy_agent_link_code: data.human_proxy_agent_link_code,
                };
                to_vec_packed(&response).map_err(|e| log_error!(e))?
            }
            AgentMessageType::AgentToAgentMergeTempEntityResponseType => {
                match state.request_type {
                    AgentHandlerRoutingRequestType::AgentToAgentMergeTempEntity(_) => {}
                    _ => {
                        return Err(log_error!(MeshError::BadState));
                    }
                }
                match reply_data {
                    AgentHandlerRoutingResponseType::AgentToAgentMergeTempEntity() => {}
                    _ => return Err(log_error!(MeshError::BadState)),
                };
                let response = AgentToAgentMergeTempEntityResponse {};
                to_vec_packed(&response).unwrap()
            }
            AgentMessageType::AgentToAgentUnlinkEntitiesResponseType => {
                match state.request_type {
                    AgentHandlerRoutingRequestType::AgentToAgentUnlinkEntities(_) => {}
                    _ => {
                        return Err(log_error!(MeshError::BadState));
                    }
                }
                match reply_data {
                    AgentHandlerRoutingResponseType::AgentToAgentUnlinkEntities() => {}
                    _ => return Err(log_error!(MeshError::BadState)),
                };
                let response = AgentToAgentUnlinkEntitiesResponse {};
                to_vec_packed(&response).unwrap()
            }
            _ => {
                return Err(log_error!(MeshError::RequestFailed(format!(
                    "invalid message type {:?}",
                    state.response_message_type
                ))))
            }
        };

        let outer_reply = state.message.build_reply(
            state.response_message_type.into(),
            MeshStatusType::Success,
            None,
            Some(outer_reply_payload),
        );
        return Ok(vec![outer_reply]);
    }

    pub fn register_link_via_delegate_handler(&mut self, request_handler: Box<RequestHandler>) {
        self.register_link_via_delegate_handler_with_authorization_check(
            authorization_is_owner_default!(),
            request_handler,
        )
    }

    pub fn register_link_via_delegate_handler_with_authorization_check(
        &mut self,
        authorization_handler: Box<AuthorizationHandler>,
        request_handler: Box<RequestHandler>,
    ) {
        let mut state = self.state.write().unwrap();
        state.default_handle_link_via_delegate_route = Some(Arc::new(RouterData {
            router_callback: Box::new(move |message| {
                message.authorization_check(&authorization_handler)?;
                request_handler(message)
            }),
        }));
    }

    pub fn register_link_via_delegate_session_handler(
        &mut self,
        request_handler: Box<RequestHandler>,
    ) {
        self.register_link_via_delegate_session_handler_with_authorization_check(
            authorization_is_owner_default!(),
            request_handler,
        )
    }

    pub fn register_link_via_delegate_session_handler_with_authorization_check(
        &mut self,
        authorization_handler: Box<AuthorizationHandler>,
        request_handler: Box<RequestHandler>,
    ) {
        let mut state = self.state.write().unwrap();
        state.default_handle_link_via_delegate_session_route = Some(Arc::new(RouterData {
            router_callback: Box::new(move |message| {
                message.authorization_check(&authorization_handler)?;
                request_handler(message)
            }),
        }));
    }

    pub fn register_link_entity_handler(&mut self, request_handler: Box<RequestHandler>) {
        self.register_link_entity_handler_with_authorization_check(
            authorization_is_owner_default!(),
            request_handler,
        )
    }

    pub fn register_link_entity_handler_with_authorization_check(
        &mut self,
        authorization_handler: Box<AuthorizationHandler>,
        request_handler: Box<RequestHandler>,
    ) {
        let mut state = self.state.write().unwrap();
        state.default_handle_link_entity_route = Some(Arc::new(RouterData {
            router_callback: Box::new(move |message| {
                message.authorization_check(&authorization_handler)?;
                request_handler(message)
            }),
        }));
    }

    pub fn register_link_entity_pre_create_handler(
        &mut self,
        request_handler: Box<RequestHandler>,
    ) {
        self.register_link_entity_pre_create_handler_with_authorization_check(
            authorization_is_owner_default!(),
            request_handler,
        )
    }

    pub fn register_link_entity_pre_create_handler_with_authorization_check(
        &mut self,
        authorization_handler: Box<AuthorizationHandler>,
        request_handler: Box<RequestHandler>,
    ) {
        let mut state = self.state.write().unwrap();
        state.default_handle_link_entity_pre_create_route = Some(Arc::new(RouterData {
            router_callback: Box::new(move |message| {
                message.authorization_check(&authorization_handler)?;
                request_handler(message)
            }),
        }));
    }

    pub fn register_link_entity_post_create_handler(
        &mut self,
        request_handler: Box<RequestHandler>,
    ) {
        let mut state = self.state.write().unwrap();
        state.default_handle_link_entity_post_create_route = Some(Arc::new(RouterData {
            router_callback: request_handler,
        }));
    }

    pub fn register_get_link_codes_handler(&mut self, request_handler: Box<RequestHandler>) {
        self.register_get_link_codes_handler_with_authorization_check(
            authorization_is_owner_default!(),
            request_handler,
        )
    }

    pub fn register_get_link_codes_handler_with_authorization_check(
        &mut self,
        authorization_handler: Box<AuthorizationHandler>,
        request_handler: Box<RequestHandler>,
    ) {
        let mut state = self.state.write().unwrap();
        state.default_handle_get_link_codes_route = Some(Arc::new(RouterData {
            router_callback: Box::new(move |message| {
                message.authorization_check(&authorization_handler)?;
                request_handler(message)
            }),
        }));
    }

    pub fn register_create_temp_entity_handler(&mut self, request_handler: Box<RequestHandler>) {
        self.register_create_temp_entity_handler_with_authorization_check(
            authorization_is_owner_default!(),
            request_handler,
        )
    }

    pub fn register_create_temp_entity_handler_with_authorization_check(
        &mut self,
        authorization_handler: Box<AuthorizationHandler>,
        request_handler: Box<RequestHandler>,
    ) {
        let mut state = self.state.write().unwrap();
        state.default_handle_create_temp_entity_route = Some(Arc::new(RouterData {
            router_callback: Box::new(move |message| {
                message.authorization_check(&authorization_handler)?;
                request_handler(message)
            }),
        }));
    }

    pub fn register_merge_temp_entity_handler(&mut self, request_handler: Box<RequestHandler>) {
        let mut state = self.state.write().unwrap();
        state.default_handle_merge_temp_entity_route = Some(Arc::new(RouterData {
            router_callback: request_handler,
        }));
    }

    pub fn register_unlink_entities_handler(&mut self, request_handler: Box<RequestHandler>) {
        self.register_unlink_entities_handler_with_authorization_check(
            authorization_is_connected_either_direction!(),
            request_handler,
        )
    }

    pub fn register_unlink_entities_handler_with_authorization_check(
        &mut self,
        authorization_handler: Box<AuthorizationHandler>,
        request_handler: Box<RequestHandler>,
    ) {
        let mut state = self.state.write().unwrap();
        state.default_handle_unlink_entities_route = Some(Arc::new(RouterData {
            router_callback: Box::new(move |message| {
                message.authorization_check(&authorization_handler)?;
                request_handler(message)
            }),
        }));
    }

    pub fn register_handler(
        &mut self,
        subsystem: MeshSubsystem,
        message_type: MeshMessageType,
        request_handler: Box<RequestHandler>,
    ) {
        self.register_handler_with_authorization_check(
            subsystem,
            message_type,
            authorization_is_owner_default!(),
            request_handler,
        )
    }

    pub fn register_handler_with_authorization_check(
        &mut self,
        subsystem: MeshSubsystem,
        message_type: MeshMessageType,
        authorization_handler: Box<AuthorizationHandler>,
        request_handler: Box<RequestHandler>,
    ) {
        self.register_handler_with_authorization_check_set_include_pre_creates(
            subsystem,
            message_type,
            authorization_handler,
            request_handler,
            false,
        )
    }

    pub fn register_handler_set_include_pre_creates(
        &mut self,
        subsystem: MeshSubsystem,
        message_type: MeshMessageType,
        request_handler: Box<RequestHandler>,
        include_pre_creates: bool,
    ) {
        self.register_handler_with_authorization_check_set_include_pre_creates(
            subsystem,
            message_type,
            authorization_is_owner_default!(),
            request_handler,
            include_pre_creates,
        )
    }

    pub fn register_handler_with_authorization_check_set_include_pre_creates(
        &mut self,
        subsystem: MeshSubsystem,
        message_type: MeshMessageType,
        authorization_handler: Box<AuthorizationHandler>,
        request_handler: Box<RequestHandler>,
        include_pre_creates: bool,
    ) {
        let mut state = self.state.write().unwrap();
        state.handler_routing_table.add_message_route(
            RouterMessageKey::new(subsystem, message_type),
            Box::new(move |message| {
                // always do auth check even if include_pre_creates is false
                message.authorization_check(&authorization_handler)?;
                if !include_pre_creates {
                    match &message.request_type {
                    AgentHandlerRoutingRequestType::AgentToAgentLinkEntityPreCreate(_) => {
                        return Ok(AgentHandlerResultData {
                            response: AgentHandlerResultDataResponse::ImmediateResponse(
                                AgentHandlerRoutingResponseType::AgentToAgentLinkEntityPreCreate(AgentToAgentLinkEntityPreCreateResponseData{ link_updates: None }),
                            ),
                            messages: vec![],
                        })
                    }
                    _ => {}
                  }
                }
                request_handler(message)
            }),
        );
    }

    pub fn register_handler_with_authorization_check_with_pre_creates(
        &mut self,
        subsystem: MeshSubsystem,
        message_type: MeshMessageType,
        authorization_handler: Box<AuthorizationHandler>,
        request_handler: Box<RequestHandler>,
        pre_create_handler: Box<RequestHandler>,
    ) {
        let mut state = self.state.write().unwrap();
        state.handler_routing_table.add_message_route(
            RouterMessageKey::new(subsystem, message_type),
            Box::new(move |message| {
                message.authorization_check(&authorization_handler)?;
                match &message.request_type {
                    AgentHandlerRoutingRequestType::AgentToAgentLinkEntityPreCreate(_) => {
                        pre_create_handler(message)
                    }
                    _ => request_handler(message),
                }
            }),
        );
    }

    fn get_pending_state(&self, state_id: MeshId) -> Option<AgentHandlerRoutingState> {
        let mut handler_state = self.state.write().unwrap();
        return handler_state.pending_request_states.remove(&state_id);
    }

    fn add_pending_state(&self, state_id: MeshId, state: AgentHandlerRoutingState) {
        let mut handler_state = self.state.write().unwrap();
        handler_state.pending_request_states.insert(state_id, state);
    }

    pub fn send_reply_for_handler(
        &self,
        state_id: MeshId,
        reply_data: AgentHandlerRoutingResponseType,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let state = self.get_pending_state(state_id);
        let mut state =
            state.ok_or_else(|| log_error!(MeshError::RouteFailed("state id not found".into())))?;
        state.reply_data = Some(reply_data);
        self.send_agent_response(state)
    }

    pub fn send_error_for_handler(
        &self,
        state_id: MeshId,
        err: MeshError,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let state = self.get_pending_state(state_id);
        let mut state =
            state.ok_or_else(|| log_error!(MeshError::RouteFailed("state id not found".into())))?;
        state.reply_error = Some(err);
        self.send_agent_response(state)
    }

    pub fn send_error_status_for_handler(
        &self,
        state_id: MeshId,
        status: MeshStatusType,
        status_message: Option<String>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let state = self.get_pending_state(state_id);
        let mut state =
            state.ok_or_else(|| log_error!(MeshError::RouteFailed("state id not found".into())))?;
        state.reply_status = Some(status);
        state.reply_status_message = status_message;
        self.send_agent_response(state)
    }

    pub fn register_default_link_via_delegate_handler(&mut self) {
        let cloned_agent = self.clone();
        self.register_link_via_delegate_handler_with_authorization_check(
            authorization_is_owner_default!(),
            Box::new(move |message| cloned_agent.handle_link_via_delegate_default(message)),
        )
    }

    pub fn register_default_link_via_delegate_handler_with_autorization_check(
        &mut self,
        authorization_handler: Box<AuthorizationHandler>,
    ) {
        let cloned_agent = self.clone();
        self.register_link_via_delegate_handler_with_authorization_check(
            authorization_handler,
            Box::new(move |message| cloned_agent.handle_link_via_delegate_default(message)),
        )
    }

    pub fn register_default_get_link_codes_handler(&mut self) {
        let cloned_agent = self.clone();
        self.register_get_link_codes_handler_with_authorization_check(
            authorization_is_owner_default!(),
            Box::new(move |message| cloned_agent.handle_get_link_codes_default(message)),
        )
    }

    pub fn register_default_get_link_codes_handler_with_autorization_check(
        &mut self,
        authorization_handler: Box<AuthorizationHandler>,
    ) {
        let cloned_agent = self.clone();
        self.register_get_link_codes_handler_with_authorization_check(
            authorization_handler,
            Box::new(move |message| cloned_agent.handle_get_link_codes_default(message)),
        )
    }

    fn handle_link_via_delegate_default(
        &self,
        request: AgentHandlerRoutingRequest,
    ) -> Result<AgentHandlerResultData, MeshError> {
        match &request.request_type {
            AgentHandlerRoutingRequestType::AgentToAgentLinkEntityViaDelegate(_data) => {}
            _ => {
                return Err(MeshError::BadState);
            }
        };
        return Ok(AgentHandlerResultData {
            messages: vec![],
            response: AgentHandlerResultDataResponse::ImmediateResponse(
                AgentHandlerRoutingResponseType::AgentToAgentLinkEntityViaDelegate(
                    AgentToAgentLinkEntityViaDelegateResponseData {
                        emid_operations: None,
                        lemid_operations: None,
                        message: None,
                        link_updates: None,
                    },
                ),
            ),
        });
    }

    fn handle_get_link_codes_default(
        &self,
        request: AgentHandlerRoutingRequest,
    ) -> Result<AgentHandlerResultData, MeshError> {
        match &request.request_type {
            AgentHandlerRoutingRequestType::AgentToAgentGetLinkCodes(_data) => {}
            _ => {
                return Err(MeshError::BadState);
            }
        };
        return Ok(AgentHandlerResultData {
            messages: vec![],
            response: AgentHandlerResultDataResponse::ImmediateResponse(
                AgentHandlerRoutingResponseType::AgentToAgentGetLinkCodes(
                    AgentToAgentGetLinkCodesResponseData {
                        message: None,
                        human_proxy_agent_link_code: None,
                    },
                ),
            ),
        });
    }
}
