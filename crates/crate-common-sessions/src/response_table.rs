use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::hash::Hash;
use core::hash::Hasher;

use hashbrown::HashMap;

use common_messages::MeshMessage;
use common_messages::MeshMessageType;
use common_messages::MeshSubsystem;
use common_sync::Mutex;
use common_types::time::get_current_time_ms;
use common_types::MeshMessageId;

use crate::routing_table::MeshStateMachineType;

const DEFAULT_EXPIRATION: i64 = 10000;
const DEFAULT_MAX_TO_EXPIRE: usize = 1000;

#[derive(PartialEq, Eq, Clone, Copy)]
struct ResponseKey {
    message_id: MeshMessageId,
}

impl Hash for ResponseKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // To be useable as a key into a HashMap, the hashes must be equal.
        Borrow::<MeshMessageId>::borrow(self).hash(state)
    }
}

impl Borrow<MeshMessageId> for ResponseKey {
    fn borrow(&self) -> &MeshMessageId {
        &self.message_id
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
struct TtlKey {
    expire_time: i64,
    id: u64,
}

pub struct ResponseData<Context> {
    pub subsystem: MeshSubsystem,
    pub message_type: MeshMessageType,
    pub mesh_state_machine: MeshStateMachineType,
    pub context: Context,
}

struct ResponseEntry<Context> {
    ttl_key: TtlKey,
    response_data: ResponseData<Context>,
}

struct TtlResponseEntry {
    key: ResponseKey,
}

struct ResponseTableInternal<Context> {
    responses: HashMap<ResponseKey, ResponseEntry<Context>>,
    expiration: BTreeMap<TtlKey, TtlResponseEntry>,
    next_id: u64,
}

#[derive(Clone)]
pub struct ResponseTable<Context> {
    state: Arc<Mutex<ResponseTableInternal<Context>>>,
}

impl<Context> ResponseTable<Context> {
    pub fn new() -> ResponseTable<Context> {
        let table = ResponseTable {
            state: Arc::new(Mutex::new(ResponseTableInternal {
                responses: HashMap::new(),
                expiration: BTreeMap::new(),
                next_id: 0,
            })),
        };
        return table;
    }

    pub fn schedule_response(
        &mut self,
        message: &MeshMessage,
        mesh_state_machine: MeshStateMachineType,
        expiration_ms: Option<i64>,
        context: Context,
    ) {
        self.schedule_response_with_response_type(
            message,
            message.header.message_type,
            mesh_state_machine,
            expiration_ms,
            context,
        );
    }

    pub fn schedule_response_with_response_type(
        &mut self,
        message: &MeshMessage,
        message_response_type: MeshMessageType,
        mesh_state_machine: MeshStateMachineType,
        expiration_ms: Option<i64>,
        context: Context,
    ) {
        let mut db = self.state.lock().unwrap();
        let expiration = expiration_ms.unwrap_or(DEFAULT_EXPIRATION);
        let ttl_key = TtlKey {
            expire_time: get_current_time_ms() + expiration,
            id: db.next_id,
        };

        db.next_id += 1;
        let response_key = ResponseKey {
            message_id: message.header.message_id.clone().into(),
        };
        let response_entry = ResponseEntry {
            ttl_key,
            response_data: ResponseData {
                subsystem: message.header.subsystem,
                message_type: message_response_type,
                mesh_state_machine,
                context,
            },
        };
        db.responses.insert(response_key, response_entry);
        let ttl_entry = TtlResponseEntry { key: response_key };
        db.expiration.insert(ttl_key, ttl_entry);
    }

    pub fn find_and_remove_response(
        &mut self,
        message_id: &MeshMessageId,
    ) -> Option<ResponseData<Context>> {
        let mut db = self.state.lock().unwrap();
        let entry = db.responses.remove(message_id);
        if let Some(entry) = entry {
            db.expiration.remove(&entry.ttl_key);
            return Some(entry.response_data);
        }
        return None;
    }

    pub fn check_purge_expired_tasks(
        &mut self,
        max_to_expire: Option<usize>,
    ) -> (Vec<ResponseData<Context>>, Option<i64>) {
        let mut next_expire: Option<i64> = None;
        let current_time = get_current_time_ms();
        let mut db = self.state.lock().unwrap();
        let db_ref = &mut *db;
        let mut stale: Vec<ResponseData<Context>> = vec![];
        let mut num_expired = 0;
        let max_to_expire = max_to_expire.unwrap_or(DEFAULT_MAX_TO_EXPIRE);
        while let Some((key, entry)) = db_ref.expiration.iter().next() {
            if key.expire_time > current_time {
                next_expire = Some(key.expire_time);
                break;
            }
            if num_expired >= max_to_expire {
                next_expire = Some(0);
                break;
            }

            num_expired += 1;
            if let Some(response_entry) = db_ref.responses.remove(&entry.key) {
                stale.push(response_entry.response_data);
            }
            let kc = key.clone();
            db_ref.expiration.remove(&kc);
        }
        return (stale, next_expire);
    }

    pub fn next_expiry(&self) -> Option<i64> {
        self.state
            .lock()
            .unwrap()
            .expiration
            .first_key_value()
            .map(|(k, _)| k.expire_time)
    }
}
