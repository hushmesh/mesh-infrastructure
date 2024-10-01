use alloc::sync::Arc;
use alloc::vec::Vec;

use hashbrown::HashMap;
use lazy_static::lazy_static;

use common_sync::RwLock;
use common_types::agent_entity_trustee_objects::AgentMeshLinkInfo;
use common_types::agent_entity_trustee_objects::AgentMeshRelationshipAndPermissions;
use common_types::agent_entity_trustee_objects::AgentMeshRelationshipAndPermissionsForLink;
use common_types::agent_entity_trustee_objects::AgentMeshRelationshipDirection;
use common_types::LinkedEntityKeychainMeshId;
use common_types::MeshId;
use common_types::MeshPermission;
use common_types::MeshRelationship;

pub struct AuthorizationPermissionsMapInternal {
    map: HashMap<MeshRelationship, Vec<MeshPermission>>,
}

pub struct AuthorizationPermissionsMap {
    state: Arc<RwLock<AuthorizationPermissionsMapInternal>>,
}

impl AuthorizationPermissionsMap {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(AuthorizationPermissionsMapInternal {
                map: HashMap::new(),
            })),
        }
    }
    pub fn add_permission(relationship: MeshRelationship, permission: MeshPermission) {
        let mut state = PERMISSIONS_MAP.state.write().unwrap();
        let permissions = state.map.entry(relationship).or_insert_with(Vec::new);
        permissions.push(permission);
    }

    pub fn get_permissions(relationship: &MeshRelationship) -> Vec<MeshPermission> {
        let state = PERMISSIONS_MAP.state.read().unwrap();
        let permissions = state.map.get(relationship).cloned().unwrap_or_default();
        permissions
    }

    pub fn get_permissions_for_link(
        relationship: &AgentMeshRelationshipAndPermissionsForLink,
    ) -> Vec<MeshPermission> {
        let state = PERMISSIONS_MAP.state.read().unwrap();
        let permissions_to_add = relationship.added_permissions.clone().unwrap_or_default();
        let permissions_to_remove = relationship.removed_permissions.clone().unwrap_or_default();
        let mut permissions: Vec<MeshPermission> = relationship
            .relationships
            .iter()
            .flat_map(|rel| state.map.get(rel).cloned().unwrap_or_default())
            .collect();
        permissions.extend(permissions_to_add);
        permissions.retain(|p| !permissions_to_remove.contains(p));
        permissions
    }

    pub fn get_permissions_for_links(
        relationships: &[AgentMeshRelationshipAndPermissionsForLink],
    ) -> Vec<MeshPermission> {
        relationships
            .iter()
            .flat_map(|relationship| {
                AuthorizationPermissionsMap::get_permissions_for_link(relationship)
            })
            .collect()
    }

    pub fn get_relationships_for_link(
        relationship: &AgentMeshRelationshipAndPermissionsForLink,
    ) -> Vec<MeshRelationship> {
        relationship.relationships.iter().cloned().collect()
    }

    pub fn get_relationships_for_links(
        relationships: &[AgentMeshRelationshipAndPermissionsForLink],
    ) -> Vec<MeshRelationship> {
        relationships
            .iter()
            .flat_map(|relationship| {
                AuthorizationPermissionsMap::get_relationships_for_link(relationship)
            })
            .collect()
    }

    pub fn has_permissions(
        relationship: MeshRelationship,
        permissions_to_find: &[MeshPermission],
    ) -> bool {
        let state = PERMISSIONS_MAP.state.read().unwrap();
        let permissions = state.map.get(&relationship);
        permissions
            .map(|p| {
                permissions_to_find
                    .iter()
                    .all(|permission| p.contains(permission))
            })
            .unwrap_or(false)
    }

    pub fn has_permission(relationship: MeshRelationship, permission: &MeshPermission) -> bool {
        let state = PERMISSIONS_MAP.state.read().unwrap();
        let permissions = state.map.get(&relationship);
        permissions
            .map(|permissions| permissions.contains(&permission))
            .unwrap_or(false)
    }
}

lazy_static! {
    static ref PERMISSIONS_MAP: AuthorizationPermissionsMap = AuthorizationPermissionsMap::new();
}

pub struct AuthorizationChecker<'a> {
    link_info: &'a Option<AgentMeshLinkInfo>,
    relationships_origin_to_self: Option<Vec<AgentMeshRelationshipAndPermissionsForLink>>,
    relationships_self_to_origin: Option<Vec<AgentMeshRelationshipAndPermissionsForLink>>,
}

impl<'a> AuthorizationChecker<'a> {
    pub fn new(link_info: &'a Option<AgentMeshLinkInfo>) -> Self {
        Self {
            link_info,
            relationships_origin_to_self: None,
            relationships_self_to_origin: None,
        }
    }

    pub fn get_relationships(
        &mut self,
        direction: AgentMeshRelationshipDirection,
    ) -> &[AgentMeshRelationshipAndPermissionsForLink] {
        &*match direction {
            AgentMeshRelationshipDirection::OriginToSelf => &mut self.relationships_origin_to_self,
            AgentMeshRelationshipDirection::SelfToOrigin => &mut self.relationships_self_to_origin,
        }
        .get_or_insert_with(|| {
            self.link_info
                .as_ref()
                .map(|link_info| link_info.get_all_relationships(direction))
                .unwrap_or_default()
        })
    }

    pub fn get_permissions(
        &mut self,
        direction: AgentMeshRelationshipDirection,
    ) -> Vec<MeshPermission> {
        let relationships = self.get_relationships(direction);
        AuthorizationPermissionsMap::get_permissions_for_links(relationships)
    }

    pub fn has_relationship(
        &mut self,
        direction: AgentMeshRelationshipDirection,
        relationship: &str,
    ) -> bool {
        let relationships = self.get_relationships(direction);
        AuthorizationPermissionsMap::get_relationships_for_links(relationships)
            .contains(&relationship.into())
    }

    pub fn has_relationships(
        &mut self,
        direction: AgentMeshRelationshipDirection,
        relationships_search: &[MeshRelationship],
    ) -> bool {
        let relationships = self.get_relationships(direction);
        AuthorizationPermissionsMap::get_relationships_for_links(relationships)
            .iter()
            .all(|relationship| relationships_search.contains(relationship))
    }

    pub fn has_relationships_any(
        &mut self,
        direction: AgentMeshRelationshipDirection,
        relationships_search: &[MeshRelationship],
    ) -> bool {
        let relationships = self.get_relationships(direction);
        AuthorizationPermissionsMap::get_relationships_for_links(relationships)
            .iter()
            .any(|relationship| relationships_search.contains(relationship))
    }

    pub fn has_relationships_any_either_direction(
        &mut self,
        relationships_search: &[MeshRelationship],
    ) -> bool {
        let relationships = self.get_relationships(AgentMeshRelationshipDirection::OriginToSelf);
        if AuthorizationPermissionsMap::get_relationships_for_links(relationships)
            .iter()
            .any(|relationship| relationships_search.contains(relationship))
        {
            return true;
        }
        let relationships = self.get_relationships(AgentMeshRelationshipDirection::SelfToOrigin);
        AuthorizationPermissionsMap::get_relationships_for_links(relationships)
            .iter()
            .any(|relationship| relationships_search.contains(relationship))
    }

    pub fn has_permission(
        &mut self,
        direction: AgentMeshRelationshipDirection,
        permission: &str,
    ) -> bool {
        self.get_permissions(direction).contains(&permission.into())
    }

    pub fn has_permissions(
        &mut self,
        direction: AgentMeshRelationshipDirection,
        permissions: &[MeshPermission],
    ) -> bool {
        self.get_permissions(direction)
            .iter()
            .all(|permission| permissions.contains(permission))
    }

    pub fn get_session_or_direct_relationship(
        &self,
        agent_ids: &[MeshId],
    ) -> Option<&AgentMeshRelationshipAndPermissions> {
        self.link_info
            .as_ref()
            .and_then(|link_info| link_info.get_session_or_direct_relationship(agent_ids))
    }

    pub fn get_session_or_direct_lemid(
        &self,
        agent_ids: &[MeshId],
    ) -> Option<LinkedEntityKeychainMeshId> {
        self.get_session_or_direct_relationship(agent_ids)
            .and_then(|r| Some(r.get_lemid()))
    }
    pub fn get_session_relationship(
        &self,
        agent_ids: &[MeshId],
    ) -> Option<&AgentMeshRelationshipAndPermissions> {
        self.link_info
            .as_ref()
            .and_then(|link_info| link_info.get_session_relationship(agent_ids))
    }

    pub fn get_session_lemid(&self, agent_ids: &[MeshId]) -> Option<LinkedEntityKeychainMeshId> {
        self.get_session_relationship(agent_ids)
            .and_then(|r| Some(r.get_lemid()))
    }

    pub fn is_authenticated_session(&self) -> bool {
        self.link_info
            .as_ref()
            .map(|link_info| link_info.is_authenticated_session())
            .unwrap_or(false)
    }

    pub fn is_authenticated_with_session_for_agent(&self, agent_ids: &[MeshId]) -> bool {
        self.is_authenticated_session() && self.get_session_relationship(agent_ids).is_some()
    }
}
