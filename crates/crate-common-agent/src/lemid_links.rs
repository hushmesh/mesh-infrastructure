use alloc::vec::Vec;

use hashbrown::hash_map::Entry;
use hashbrown::HashMap;

use common_messages::agent_trustee_messages::SessionLinkCodeSegment;
use common_types::log_error;
use common_types::LinkedEntityKeychainMeshId;
use common_types::MeshError;
use common_types::MeshId;
use common_types::MeshLinkCode;

use crate::agent::LookupLinkedEntitiesResult;

#[derive(Debug, Clone)]
pub struct LemidLink {
    pub lemid: LinkedEntityKeychainMeshId,
    pub session_link_code_created_with: Option<MeshLinkCode>,
}

#[derive(Debug, Clone)]
pub struct LemidLinks {
    pub links_by_agent_id: HashMap<MeshId, Vec<LemidLink>>,
    pub links_by_link_code: HashMap<MeshLinkCode, LemidLink>,
    pub links_by_link_code_postfix: HashMap<SessionLinkCodeSegment, LemidLink>,
}

impl LemidLinks {
    pub fn new() -> LemidLinks {
        LemidLinks {
            links_by_agent_id: HashMap::new(),
            links_by_link_code: HashMap::new(),
            links_by_link_code_postfix: HashMap::new(),
        }
    }

    pub fn add_lemid(&mut self, agent_id: MeshId, lemid: LinkedEntityKeychainMeshId) {
        self.add_link(
            agent_id,
            LemidLink {
                lemid,
                session_link_code_created_with: None,
            },
        );
    }

    pub fn add_lemid_with_link_code(
        &mut self,
        agent_id: MeshId,
        lemid: LinkedEntityKeychainMeshId,
        session_link_code_created_with: Option<MeshLinkCode>,
    ) {
        self.add_link(
            agent_id,
            LemidLink {
                lemid,
                session_link_code_created_with,
            },
        );
    }

    pub fn add_link(&mut self, agent_id: MeshId, link: LemidLink) {
        if let Some(link_code) = link.session_link_code_created_with {
            self.links_by_link_code.insert(link_code, link.clone());
            let postfix = link_code.id[16..]
                .try_into()
                .expect("slice with incorrect length");
            self.links_by_link_code_postfix
                .insert(postfix, link.clone());
        }
        match self.links_by_agent_id.entry(agent_id) {
            Entry::Occupied(mut oe) => {
                let links = oe.get_mut();
                if !links.iter().any(|l| l.lemid == link.lemid) {
                    links.push(link);
                }
            }
            Entry::Vacant(ve) => {
                ve.insert(vec![link]);
            }
        }
    }

    pub fn get_link_with_postfix(
        &self,
        postfix: SessionLinkCodeSegment,
    ) -> Result<LinkedEntityKeychainMeshId, MeshError> {
        self.links_by_link_code_postfix
            .get(&postfix)
            .map(|link| link.lemid)
            .ok_or_else(|| {
                log_error!(MeshError::RequestFailed(
                    "link not found for postfix".into(),
                ))
            })
    }

    pub fn get_link(
        &self,
        agent_id: MeshId,
        lemid: Option<LinkedEntityKeychainMeshId>,
    ) -> Result<LinkedEntityKeychainMeshId, MeshError> {
        let links = self.links_by_agent_id.get(&agent_id);
        match links {
            Some(links) => {
                if links.is_empty() {
                    Err(log_error!(MeshError::RequestFailed(
                        "link not found for agent_id".into(),
                    )))
                } else if lemid.is_none() {
                    Ok(links[0].lemid)
                } else {
                    Ok(links
                        .iter()
                        .find(|link| link.lemid == lemid.unwrap())
                        .map(|link| link.lemid)
                        .ok_or_else(|| {
                            log_error!(MeshError::RequestFailed(
                                "link not found for agent_id".into(),
                            ))
                        })?)
                }
            }
            None => Err(log_error!(MeshError::RequestFailed(
                "link not found for agent_id".into(),
            ))),
        }
    }

    pub fn get_links(&self, agent_id: MeshId) -> Vec<LinkedEntityKeychainMeshId> {
        self.links_by_agent_id
            .get(&agent_id)
            .map(|links| links.iter().map(|link| link.lemid).collect())
            .unwrap_or_else(|| Vec::new())
    }

    pub fn get_lemid_for_link_code(
        &self,
        link_code: MeshLinkCode,
    ) -> Option<LinkedEntityKeychainMeshId> {
        self.links_by_link_code
            .get(&link_code)
            .map(|link| link.lemid)
    }
}

impl From<LookupLinkedEntitiesResult> for LemidLinks {
    fn from(result: LookupLinkedEntitiesResult) -> LemidLinks {
        let mut lemid_links = LemidLinks::new();
        for entity in result.entities {
            lemid_links.add_link(
                entity.agent_id,
                LemidLink {
                    lemid: entity.lemid,
                    session_link_code_created_with: entity.session_link_code_created_with,
                },
            )
        }
        lemid_links
    }
}
