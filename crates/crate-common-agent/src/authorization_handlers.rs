use common_types::agent_entity_trustee_objects::AgentMeshLinkInfo;
use common_types::agent_entity_trustee_objects::AgentMeshRelationshipDirection;
use common_types::relationships::RELATIONSHIP_CONNECTED;
use common_types::relationships::RELATIONSHIP_OWNER;
use common_types::MeshError;
use common_types::MeshId;
use common_types::MeshLinkAttributesType;
use common_types::MeshPermission;
use common_types::MeshRelationship;

use crate::agent::AgentHandlerRoutingRequest;
use crate::authorization::AuthorizationChecker;

pub fn authorization_no_precheck_check(
    _request: &AgentHandlerRoutingRequest,
    _link_info: &Option<AgentMeshLinkInfo>,
) -> Result<(), MeshError> {
    Ok(())
}

pub fn authorization_is_owner_check(
    request: &AgentHandlerRoutingRequest,
    link_info: &Option<AgentMeshLinkInfo>,
    direction: AgentMeshRelationshipDirection,
) -> Result<(), MeshError> {
    authorization_has_relationships_any_check(
        request,
        link_info,
        Some(direction),
        &vec![RELATIONSHIP_OWNER.into()],
    )
}

pub fn authorization_is_connected_check(
    request: &AgentHandlerRoutingRequest,
    link_info: &Option<AgentMeshLinkInfo>,
) -> Result<(), MeshError> {
    authorization_has_relationships_any_check(
        request,
        link_info,
        Some(AgentMeshRelationshipDirection::OriginToSelf),
        &vec![RELATIONSHIP_OWNER.into(), RELATIONSHIP_CONNECTED.into()],
    )
}

pub fn authorization_is_connected_check_either_direction(
    request: &AgentHandlerRoutingRequest,
    link_info: &Option<AgentMeshLinkInfo>,
) -> Result<(), MeshError> {
    authorization_has_relationships_any_check_either_direction(
        request,
        link_info,
        &vec![RELATIONSHIP_OWNER.into(), RELATIONSHIP_CONNECTED.into()],
    )
}

pub fn authorization_is_connected_and_from_agents_check(
    request: &AgentHandlerRoutingRequest,
    link_info: &Option<AgentMeshLinkInfo>,
    agent_ids: &[MeshId],
) -> Result<(), MeshError> {
    authorization_is_connected_check(request, link_info)?;
    authorization_from_agents_check(request, link_info, agent_ids)
}

pub fn authorization_has_relationship_check(
    _request: &AgentHandlerRoutingRequest,
    link_info: &Option<AgentMeshLinkInfo>,
    direction: Option<AgentMeshRelationshipDirection>,
    relationship: &str,
) -> Result<(), MeshError> {
    let mut authorizer = AuthorizationChecker::new(link_info);
    if !authorizer.has_relationship(
        direction.unwrap_or(AgentMeshRelationshipDirection::OriginToSelf),
        relationship,
    ) {
        Err(MeshError::RequestDenied)
    } else {
        Ok(())
    }
}

pub fn authorization_has_relationships_check(
    _request: &AgentHandlerRoutingRequest,
    link_info: &Option<AgentMeshLinkInfo>,
    direction: Option<AgentMeshRelationshipDirection>,
    relationships: &[MeshRelationship],
) -> Result<(), MeshError> {
    let mut authorizer = AuthorizationChecker::new(link_info);
    if !authorizer.has_relationships(
        direction.unwrap_or(AgentMeshRelationshipDirection::OriginToSelf),
        relationships,
    ) {
        Err(MeshError::RequestDenied)
    } else {
        Ok(())
    }
}

pub fn authorization_has_relationships_any_check(
    _request: &AgentHandlerRoutingRequest,
    link_info: &Option<AgentMeshLinkInfo>,
    direction: Option<AgentMeshRelationshipDirection>,
    relationships: &[MeshRelationship],
) -> Result<(), MeshError> {
    let mut authorizer = AuthorizationChecker::new(link_info);
    if !authorizer.has_relationships_any(
        direction.unwrap_or(AgentMeshRelationshipDirection::OriginToSelf),
        relationships,
    ) {
        Err(MeshError::RequestDenied)
    } else {
        Ok(())
    }
}

pub fn authorization_has_relationships_any_check_either_direction(
    _request: &AgentHandlerRoutingRequest,
    link_info: &Option<AgentMeshLinkInfo>,
    relationships: &[MeshRelationship],
) -> Result<(), MeshError> {
    let mut authorizer = AuthorizationChecker::new(link_info);
    if !authorizer.has_relationships_any_either_direction(relationships) {
        Err(MeshError::RequestDenied)
    } else {
        Ok(())
    }
}

pub fn authorization_has_permission_check(
    _request: &AgentHandlerRoutingRequest,
    link_info: &Option<AgentMeshLinkInfo>,
    direction: Option<AgentMeshRelationshipDirection>,
    permission: &str,
) -> Result<(), MeshError> {
    let mut authorizer = AuthorizationChecker::new(link_info);
    if !authorizer.has_permission(
        direction.unwrap_or(AgentMeshRelationshipDirection::OriginToSelf),
        permission,
    ) {
        Err(MeshError::RequestDenied)
    } else {
        Ok(())
    }
}

pub fn authorization_has_permissions_check(
    _request: &AgentHandlerRoutingRequest,
    link_info: &Option<AgentMeshLinkInfo>,
    direction: Option<AgentMeshRelationshipDirection>,
    permissions: &[MeshPermission],
) -> Result<(), MeshError> {
    let mut authorizer = AuthorizationChecker::new(link_info);
    if !authorizer.has_permissions(
        direction.unwrap_or(AgentMeshRelationshipDirection::OriginToSelf),
        permissions,
    ) {
        Err(MeshError::RequestDenied)
    } else {
        Ok(())
    }
}

pub fn authorization_from_agents_check(
    request: &AgentHandlerRoutingRequest,
    _link_info: &Option<AgentMeshLinkInfo>,
    agent_ids: &[MeshId],
) -> Result<(), MeshError> {
    agent_ids
        .contains(&request.source_trusteee_or_agent_id)
        .then(|| ())
        .ok_or(MeshError::RequestDenied)
}

pub fn authorization_from_agents_and_is_hushmesh_admin_check(
    request: &AgentHandlerRoutingRequest,
    _link_info: &Option<AgentMeshLinkInfo>,
    agent_ids: &[MeshId],
) -> Result<(), MeshError> {
    agent_ids
        .contains(&request.source_trusteee_or_agent_id)
        .then(|| ())
        .ok_or(MeshError::RequestDenied)?;
    let link_info = request.get_link_info();
    if let Some(link_info) = link_info {
        if !link_info.has_attribute_origin(MeshLinkAttributesType::IsHumanMeshAdmin) {
            return Err(MeshError::RequestDenied);
        }
    } else {
        return Err(MeshError::RequestDenied);
    }
    Ok(())
}

pub fn authorization_from_agents_and_is_owner_check(
    request: &AgentHandlerRoutingRequest,
    _link_info: &Option<AgentMeshLinkInfo>,
    agent_ids: &[MeshId],
) -> Result<(), MeshError> {
    agent_ids
        .contains(&request.source_trusteee_or_agent_id)
        .then(|| ())
        .ok_or(MeshError::RequestDenied)?;
    let link_info = request.get_link_info();
    authorization_has_relationships_any_check(
        request,
        link_info,
        Some(common_types::agent_entity_trustee_objects::AgentMeshRelationshipDirection::OriginToSelf),
        &vec![RELATIONSHIP_OWNER.into()],
    )
}

pub fn authorization_is_authenticated_session_check(
    _request: &AgentHandlerRoutingRequest,
    link_info: &Option<AgentMeshLinkInfo>,
) -> Result<(), MeshError> {
    let authorizer = AuthorizationChecker::new(link_info);
    if !authorizer.is_authenticated_session() {
        Err(MeshError::RequestDenied)
    } else {
        Ok(())
    }
}

pub fn authorization_is_authenticated_session_for_agent_check(
    _request: &AgentHandlerRoutingRequest,
    link_info: &Option<AgentMeshLinkInfo>,
    agent_ids: &[MeshId],
) -> Result<(), MeshError> {
    let authorizer = AuthorizationChecker::new(link_info);
    if !authorizer.is_authenticated_with_session_for_agent(agent_ids) {
        Err(MeshError::RequestDenied)
    } else {
        Ok(())
    }
}

#[macro_export]
macro_rules! authorization_no_precheck {
    () => {
        ::alloc::boxed::Box::new(|request, link_info| {
            $crate::authorization_handlers::authorization_no_precheck_check(request, link_info)
        })
    };
}

#[macro_export]
macro_rules! authorization_is_owner {
    () => {
        ::alloc::boxed::Box::new(|request, link_info| {
            $crate::authorization_handlers::authorization_is_owner_check(
                request,
                link_info,
                common_types::agent_entity_trustee_objects::AgentMeshRelationshipDirection::OriginToSelf,
            )
        })
    };
}

#[macro_export]
macro_rules! authorization_is_any_direction_owner {
    () => {
        ::alloc::boxed::Box::new(|request, link_info| {
            $crate::authorization_handlers::authorization_is_owner_any_direction_check(
                request, link_info,
            )
        })
    };
}

#[macro_export]
macro_rules! authorization_is_connected {
    () => {
        ::alloc::boxed::Box::new(|request, link_info| {
            $crate::authorization_handlers::authorization_is_connected_check(request, link_info)
        })
    };
}

#[macro_export]
macro_rules! authorization_is_connected_either_direction {
    () => {
        ::alloc::boxed::Box::new(|request, link_info| {
            $crate::authorization_handlers::authorization_is_connected_check_either_direction(
                request, link_info,
            )
        })
    };
}

#[macro_export]
macro_rules! authorization_has_relationship {
    ($direction:expr, $relationship:expr) => {
        ::alloc::boxed::Box::new(|request, link_info| {
            $crate::authorization_handlers::authorization_has_relationship_check(
                request,
                link_info,
                $direction,
                $relationship,
            )
        })
    };
}

#[macro_export]
macro_rules! authorization_has_permission {
    ($direction:expr, $permission:expr) => {
        ::alloc::boxed::Box::new(|request, link_info| {
            $crate::authorization_handlers::authorization_has_relationship_check(
                request,
                link_info,
                $direction,
                $permission,
            )
        })
    };
}

#[macro_export]
macro_rules! authorization_has_relationships {
    ($direction:expr, $relationships:expr) => {
        ::alloc::boxed::Box::new(|request, link_info| {
            $crate::authorization_handlers::authorization_has_relationships_check(
                request,
                link_info,
                $direction,
                $relationships,
            )
        })
    };
}

#[macro_export]
macro_rules! authorization_has_permissions {
    ($direction:expr, $permissions:expr) => {
        ::alloc::boxed::Box::new(|request, link_info| {
            $crate::authorization_handlers::authorization_has_relationship_check(
                request,
                link_info,
                $direction,
                $permissions,
            )
        })
    };
}

#[macro_export]
macro_rules! authorization_from_agents {
    ([$($id:expr),*]) => {{
        let ids = [$($id,)*];
        ::alloc::boxed::Box::new(move |request, link_info| {
            $crate::authorization_handlers::authorization_from_agents_check(
                request, link_info, &ids,
            )
        })
    }};
}

#[macro_export]
macro_rules! authorization_from_agents_and_is_hushmesh_admin {
    ([$($id:expr),*]) => {{
        let ids = [$($id,)*];
        ::alloc::boxed::Box::new(move |request, link_info| {
            $crate::authorization_handlers::authorization_from_agents_and_is_hushmesh_admin_check(
                request, link_info, &ids,
            )
        })
    }};
}

#[macro_export]
macro_rules! authorization_from_agents_and_is_owner {
    ([$($id:expr),*]) => {{
        let ids = [$($id,)*];
        ::alloc::boxed::Box::new(move |request, link_info| {
            $crate::authorization_handlers::authorization_from_agents_and_is_owner_check(
                request, link_info, &ids,
            )
        })
    }};
}

#[macro_export]
macro_rules! authorization_is_authenticated_session {
    () => {
        ::alloc::boxed::Box::new(|request, link_info| {
            $crate::authorization_handlers::authorization_is_authenticated_session_check(
                request, link_info,
            )
        })
    };
}

#[macro_export]
macro_rules! authorization_is_connected_and_from_agents {
    ([$($id:expr),*]) => {{
        let ids = [$($id,)*];
        ::alloc::boxed::Box::new(move |request, link_info| {
            $crate::authorization_handlers::authorization_is_connected_and_from_agents_check(
                request, link_info, &ids,
            )
        })
    }};
}

#[macro_export]
macro_rules! authorization_is_authenticated_session_for_agent {
    ($id:expr) => {
        ::alloc::boxed::Box::new(|request, link_info| {
            $crate::authorization_handlers::authorization_is_authenticated_session_for_agent_check(
                request, link_info, $id,
            )
        })
    };
}
