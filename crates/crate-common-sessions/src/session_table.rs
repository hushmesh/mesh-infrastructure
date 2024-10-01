use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::hash::Hash;
use core::hash::Hasher;
use core::num::NonZeroU64;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

use hashbrown::HashMap;

use common_sync::Mutex;
use common_types::time::get_current_time_ms;
use common_types::MeshSessionId;

const DEFAULT_EXPIRATION: i64 = 3600000;
const DEFAULT_MAX_TO_EXPIRE: usize = 1000;
const DEFAULT_MAX_TO_PING: usize = 1000;

#[derive(PartialEq, Eq, Clone, Copy)]
struct SessionKey {
    session_id: MeshSessionId,
}

impl Hash for SessionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Borrow::<MeshSessionId>::borrow(self).hash(state)
    }
}

impl Borrow<MeshSessionId> for SessionKey {
    fn borrow(&self) -> &MeshSessionId {
        &self.session_id
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
struct TtlKey {
    expire_time: i64,
    id: NonZeroU64,
}

impl TtlKey {
    fn new(duration_ms: i64) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        // Safety: NEXT_ID won't overflow for thousands of years.
        let id = unsafe { NonZeroU64::new_unchecked(NEXT_ID.fetch_add(1, Ordering::Relaxed)) };
        Self {
            expire_time: get_current_time_ms().saturating_add(duration_ms),
            id,
        }
    }
}

#[derive(Clone)]
pub struct SessionData<T> {
    pub data: T,
}

struct SessionEntry<T> {
    ttl_key: TtlKey,
    ping_ttl_key: Option<TtlKey>,
    session_data: SessionData<T>,
    expiration: i64,
    ping_expiration: Option<i64>,
}

#[derive(Clone, Copy)]
struct TtlSessionEntry {
    key: SessionKey,
}

struct SessionTableInternal<T>
where
    T: Send + Sync + Clone,
{
    sessions: HashMap<SessionKey, SessionEntry<T>>,
    sessions_expire: BTreeMap<TtlKey, TtlSessionEntry>,
    sessions_ping: BTreeMap<TtlKey, TtlSessionEntry>,
}

#[derive(Clone)]
pub struct SessionTable<T>
where
    T: Send + Sync + Clone,
{
    state: Arc<Mutex<SessionTableInternal<T>>>,
}

impl<T> SessionTable<T>
where
    T: Send + Sync + Clone,
{
    pub fn new() -> SessionTable<T> {
        SessionTable {
            state: Arc::new(Mutex::new(SessionTableInternal {
                sessions: Default::default(),
                sessions_expire: Default::default(),
                sessions_ping: Default::default(),
            })),
        }
    }

    pub fn add_session(
        &mut self,
        session_id: MeshSessionId,
        expiration_ms: Option<i64>,
        ping_ms: Option<i64>,
        data: T,
    ) {
        let expiration = expiration_ms.unwrap_or(DEFAULT_EXPIRATION);
        let ttl_key = TtlKey::new(expiration);
        let session_entry = SessionEntry {
            ttl_key,
            ping_ttl_key: ping_ms.map(TtlKey::new),
            session_data: SessionData { data },
            expiration,
            ping_expiration: ping_ms,
        };
        let session_key = SessionKey { session_id };
        let ttl_entry = TtlSessionEntry { key: session_key };

        let mut db = self.state.lock().unwrap();
        db.sessions_expire.insert(ttl_key, ttl_entry);
        if let Some(ping_ttl_key) = session_entry.ping_ttl_key {
            db.sessions_ping.insert(ping_ttl_key, ttl_entry);
        }
        db.sessions.insert(session_key, session_entry);
    }

    pub fn find_session(
        &mut self,
        session_id: &MeshSessionId,
        reset_ttl: bool,
        reset_ping: bool,
    ) -> Option<T> {
        let ref mut db = *self.state.lock().unwrap();

        let session = db.sessions.get_mut(session_id)?;
        if reset_ttl {
            db.sessions_expire.remove(&session.ttl_key);
            session.ttl_key = TtlKey::new(session.expiration);
            let expire_entry = TtlSessionEntry {
                key: SessionKey {
                    session_id: session_id.clone(),
                },
            };
            db.sessions_expire.insert(session.ttl_key, expire_entry);
        }

        if let (true, Some(ping_expiration)) = (reset_ping, session.ping_expiration) {
            let ping_ttl_key = TtlKey::new(ping_expiration);
            if let Some(old_ping_ttl_key) = session.ping_ttl_key.replace(ping_ttl_key) {
                db.sessions_ping.remove(&old_ping_ttl_key);
            }
            let ping_entry = TtlSessionEntry {
                key: SessionKey {
                    session_id: session_id.clone(),
                },
            };
            db.sessions_ping.insert(ping_ttl_key, ping_entry);
        }

        Some(session.session_data.data.clone())
    }

    pub fn remove_session(&mut self, session_id: &MeshSessionId) -> Option<T> {
        let mut db = self.state.lock().unwrap();
        let entry = db.sessions.remove(session_id)?;
        db.sessions_expire.remove(&entry.ttl_key);
        if let Some(ping_ttl_key) = &entry.ping_ttl_key {
            db.sessions_ping.remove(ping_ttl_key);
        }
        Some(entry.session_data.data)
    }

    pub fn clear(&mut self) {
        let mut db = self.state.lock().unwrap();
        db.sessions.clear();
        db.sessions_expire.clear();
        db.sessions_ping.clear();
    }

    pub fn keys(&self) -> Vec<MeshSessionId> {
        self.state
            .lock()
            .unwrap()
            .sessions
            .keys()
            .map(|key| key.session_id)
            .collect()
    }

    pub fn values(&self) -> Vec<T> {
        self.state
            .lock()
            .unwrap()
            .sessions
            .values()
            .map(|entry| entry.session_data.data.clone())
            .collect()
    }

    pub fn check_purge_expired_tasks(
        &mut self,
        max_to_expire: Option<usize>,
    ) -> (Vec<T>, Option<i64>) {
        let mut next_expire: Option<i64> = None;
        let current_time = get_current_time_ms();
        let mut db = self.state.lock().unwrap();
        let db_ref = &mut *db;
        let mut num_expired = 0;
        let mut sessions: Vec<T> = vec![];
        let max_to_expire = max_to_expire.unwrap_or(DEFAULT_MAX_TO_EXPIRE);
        while let Some((key, entry)) = db_ref.sessions_expire.iter().next() {
            if key.expire_time > current_time {
                next_expire = Some(key.expire_time);
                break;
            }
            if num_expired >= max_to_expire {
                next_expire = Some(0);
                break;
            }

            num_expired += 1;
            let entry = db_ref.sessions.remove(&entry.key);
            if let Some(entry) = entry {
                if let Some(ping_ttl_key) = entry.ping_ttl_key {
                    db_ref.sessions_ping.remove(&ping_ttl_key);
                }
                sessions.push(entry.session_data.data);
            }
            let kc = key.clone();
            db_ref.sessions_expire.remove(&kc);
        }
        return (sessions, next_expire);
    }

    pub fn get_sessions_to_ping(&mut self, max_to_ping: Option<usize>) -> (Vec<T>, Option<i64>) {
        let mut next_ping: Option<i64> = None;
        let current_time = get_current_time_ms();
        let mut db = self.state.lock().unwrap();
        let db_ref = &mut *db;
        let mut num_pinged = 0;
        let mut sessions: Vec<T> = vec![];
        let max_to_ping = max_to_ping.unwrap_or(DEFAULT_MAX_TO_PING);
        while let Some((key, entry)) = db_ref.sessions_ping.iter().next() {
            if key.expire_time > current_time {
                next_ping = Some(key.expire_time);
                break;
            }
            if num_pinged >= max_to_ping {
                next_ping = Some(0);
                break;
            }

            num_pinged += 1;
            let session_key = entry.key;
            let entry = db_ref.sessions.get_mut(&session_key);
            if let Some(entry) = entry {
                if let Some(old_ping_ttl_key) = entry.ping_ttl_key {
                    db_ref.sessions_ping.remove(&old_ping_ttl_key);
                    let expiration = entry.ping_expiration.unwrap_or(DEFAULT_EXPIRATION);
                    let ping_ttl_key = TtlKey::new(expiration);
                    entry.ping_ttl_key = Some(ping_ttl_key);
                    let ping_ttl_entry = TtlSessionEntry { key: session_key };
                    db_ref.sessions_ping.insert(ping_ttl_key, ping_ttl_entry);
                }
                sessions.push(entry.session_data.data.clone());
            }
        }
        return (sessions, next_ping);
    }
}
