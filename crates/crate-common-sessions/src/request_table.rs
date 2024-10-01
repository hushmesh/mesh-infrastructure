use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::hash::Hash;
use core::hash::Hasher;

use hashbrown::HashMap;
use log::error;

use common_messages::MeshMessage;
use common_sync::Mutex;
use common_types::time::get_current_time_ms;
use common_types::MeshError;
use common_types::MeshMessageId;

const DEFAULT_EXPIRATION: i64 = 10000;
const DEFAULT_MAX_TO_EXPIRE: usize = 1000;

#[derive(PartialEq, Eq, Clone, Copy)]
struct RequestKey {
    message_id: MeshMessageId,
}

impl Hash for RequestKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // To be useable as a key into a HashMap, the hashes must be equal.
        Borrow::<MeshMessageId>::borrow(self).hash(state)
    }
}

impl Borrow<MeshMessageId> for RequestKey {
    fn borrow(&self) -> &MeshMessageId {
        &self.message_id
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
struct TtlKey {
    expire_time: i64,
    id: u64,
}

pub struct RequestData {
    pub reply_callback: Box<
        dyn FnOnce(Result<MeshMessage, MeshError>) -> Result<Vec<MeshMessage>, MeshError> + Send,
    >,
}
struct RequestEntry {
    ttl_key: TtlKey,
    request_data: RequestData,
}

struct TtlRequestEntry {
    key: RequestKey,
}

struct RequestTableInternal {
    requests: HashMap<RequestKey, RequestEntry>,
    requests_expire: BTreeMap<TtlKey, TtlRequestEntry>,
    next_id: u64,
}

#[derive(Clone)]
pub struct RequestTable {
    state: Arc<Mutex<RequestTableInternal>>,
}

impl RequestTable {
    pub fn new() -> RequestTable {
        RequestTable {
            state: Arc::new(Mutex::new(RequestTableInternal {
                requests: HashMap::new(),
                requests_expire: BTreeMap::new(),
                next_id: 0,
            })),
        }
    }

    pub fn add_request(
        &mut self,
        message_id: MeshMessageId,
        expiration_ms: Option<i64>,
        reply_callback: Box<
            dyn FnOnce(Result<MeshMessage, MeshError>) -> Result<Vec<MeshMessage>, MeshError>
                + Send,
        >,
    ) {
        let mut db = self.state.lock().unwrap();
        let expiration = expiration_ms.unwrap_or(DEFAULT_EXPIRATION);
        let ttl_key = TtlKey {
            expire_time: get_current_time_ms() + expiration,
            id: db.next_id,
        };

        db.next_id += 1;
        let request_key = RequestKey { message_id };
        let request_entry = RequestEntry {
            ttl_key,
            request_data: RequestData { reply_callback },
        };
        db.requests.insert(request_key, request_entry);
        let ttl_entry = TtlRequestEntry { key: request_key };
        db.requests_expire.insert(ttl_key, ttl_entry);
    }

    pub fn find_and_remove_request(&mut self, message_id: &MeshMessageId) -> Option<RequestData> {
        let mut state = self.state.lock().unwrap();
        let entry = state.requests.remove(message_id);
        if let Some(entry) = entry {
            state.requests_expire.remove(&entry.ttl_key);
            Some(entry.request_data)
        } else {
            None
        }
    }

    pub fn reset_request_ttl(&mut self, message_id: MeshMessageId, expiration: i64) {
        let mut db = self.state.lock().unwrap();
        let next_id = db.next_id;
        db.next_id += 1;
        let request_key = RequestKey { message_id };
        let request_entry = db.requests.get_mut(&request_key);

        if let Some(request_entry) = request_entry {
            let old_ttl_key = request_entry.ttl_key;
            let ttl_key = TtlKey {
                expire_time: get_current_time_ms() + expiration,
                id: next_id,
            };
            request_entry.ttl_key = ttl_key;
            db.requests_expire.remove(&old_ttl_key);
            let ttl_entry = TtlRequestEntry { key: request_key };
            db.requests_expire.insert(ttl_key, ttl_entry);
        }
    }

    pub fn remove_request(&mut self, message_id: MeshMessageId) {
        let mut db = self.state.lock().unwrap();
        if let Some(entry) = db.requests.remove(&RequestKey { message_id }) {
            db.requests_expire.remove(&entry.ttl_key);
        }
    }

    pub fn check_purge_expired_tasks(
        &mut self,
        max_to_expire: Option<usize>,
    ) -> (Vec<MeshMessage>, Option<i64>) {
        let mut next_expire: Option<i64> = None;
        let current_time = get_current_time_ms();
        let mut expired: Vec<RequestEntry> = vec![];
        {
            let mut db = self.state.lock().unwrap();
            let db_ref = &mut *db;
            let mut num_expired = 0;
            let max_to_expire = max_to_expire.unwrap_or(DEFAULT_MAX_TO_EXPIRE);
            while let Some((key, entry)) = db_ref.requests_expire.iter().next() {
                if key.expire_time > current_time {
                    next_expire = Some(key.expire_time);
                    break;
                } else if num_expired >= max_to_expire {
                    next_expire = Some(0);
                    break;
                }

                num_expired += 1;
                if let Some(request_entry) = db_ref.requests.remove(&entry.key) {
                    expired.push(request_entry);
                }
                let kc = key.clone();
                db_ref.requests_expire.remove(&kc);
            }
        }
        let mut messages: Vec<MeshMessage> = vec![];
        for entry in expired {
            let result = (entry.request_data.reply_callback)(Err(MeshError::TimeoutError));
            match result {
                Err(err) => {
                    error!("Error in request timeout callback: {}", err);
                }
                Ok(mut timeout_messages) => {
                    messages.append(&mut timeout_messages);
                }
            }
        }
        return (messages, next_expire);
    }

    pub fn next_expiry(&self) -> Option<i64> {
        self.state
            .lock()
            .unwrap()
            .requests_expire
            .first_key_value()
            .map(|(k, _)| k.expire_time)
    }
}
