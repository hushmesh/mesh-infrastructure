use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::hash::Hash;

use common_messages::MeshMessage;
use common_messages::MeshMessageType;
use common_messages::MeshSubsystem;
use common_sync::RwLock;
use common_types::MeshError;
use hashbrown::HashMap;
use hashbrown::HashSet;

pub type MeshStateMachineType = u16;

pub type RoutingTable =
    RoutingTableGeneric<RouterMessageKey, MeshMessage, Result<Vec<MeshMessage>, MeshError>, ()>;

pub type RequestResponseRoutingTable<Context> = RoutingTableGeneric<
    RouterMessageKey,
    MeshMessage,
    Result<Vec<MeshMessage>, MeshError>,
    Context,
>;

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub struct RouterMessageKey {
    pub subsystem: MeshSubsystem,
    pub message_type: MeshMessageType,
}

impl RouterMessageKey {
    pub fn new(subsystem: MeshSubsystem, message_type: MeshMessageType) -> RouterMessageKey {
        RouterMessageKey {
            subsystem,
            message_type,
        }
    }
}

impl<Context> RequestResponseRoutingTable<Context> {
    pub fn add_route(
        &mut self,
        subsystem: MeshSubsystem,
        message_type: MeshMessageType,
        callback: Box<dyn Fn(MeshMessage) -> Result<Vec<MeshMessage>, MeshError> + Send + Sync>,
    ) {
        return self.add_message_route(RouterMessageKey::new(subsystem, message_type), callback);
    }

    pub fn add_response_route(
        &mut self,
        subsystem: MeshSubsystem,
        message_type: MeshMessageType,
        state_machine_type: MeshStateMachineType,
        callback: Box<
            dyn Fn(
                    Result<MeshMessage, MeshError>,
                    MeshStateMachineType,
                    Context,
                ) -> Result<Vec<MeshMessage>, MeshError>
                + Send
                + Sync,
        >,
    ) {
        return self.add_response_message_route(
            RouterMessageKey::new(subsystem, message_type),
            state_machine_type,
            callback,
        );
    }

    pub fn find_route(
        &self,
        subsystem: MeshSubsystem,
        message_type: MeshMessageType,
    ) -> Option<Arc<RouterData<MeshMessage, Result<Vec<MeshMessage>, MeshError>>>> {
        return self.find_message_route(&RouterMessageKey::new(subsystem, message_type));
    }

    pub fn find_response_route(
        &self,
        subsystem: MeshSubsystem,
        message_type: MeshMessageType,
        state_machine_type: MeshStateMachineType,
    ) -> Option<Arc<ResponseRouterData<MeshMessage, Result<Vec<MeshMessage>, MeshError>, Context>>>
    {
        return self.find_response_message_route(
            RouterMessageKey::new(subsystem, message_type),
            state_machine_type,
        );
    }
}

pub struct RouterData<Input, Output> {
    pub router_callback: Box<dyn Fn(Input) -> Output + Send + Sync>,
}

pub struct ResponseRouterData<Input, Output, Context> {
    pub router_callback: Box<
        dyn Fn(Result<Input, MeshError>, MeshStateMachineType, Context) -> Output + Send + Sync,
    >,
}

struct RouterEntry<Input, Output> {
    router_data: Arc<RouterData<Input, Output>>,
}

struct ResponseRouterEntry<Input, Output, Context> {
    router_data: Arc<ResponseRouterData<Input, Output, Context>>,
}

struct RoutingTableInternal<K, Input, Output, Context> {
    request_routes: HashMap<K, RouterEntry<Input, Output>>,
    response_routes:
        HashMap<(K, MeshStateMachineType), ResponseRouterEntry<Input, Output, Context>>,
    response_states: HashSet<MeshStateMachineType>,
}

#[derive(Clone)]
pub struct RoutingTableGeneric<K, Input, Output, Context> {
    state: Arc<RwLock<RoutingTableInternal<K, Input, Output, Context>>>,
}

impl<K: Eq + Hash, Input: Send + Sync + 'static, Output: Send + Sync + 'static, Context>
    RoutingTableGeneric<K, Input, Output, Context>
{
    pub fn new() -> RoutingTableGeneric<K, Input, Output, Context> {
        let table = RoutingTableGeneric {
            state: Arc::new(RwLock::new(RoutingTableInternal {
                request_routes: HashMap::new(),
                response_routes: HashMap::new(),
                response_states: HashSet::new(),
            })),
        };
        return table;
    }

    pub fn add_message_route(
        &mut self,
        route_key: K,
        router_callback: Box<dyn Fn(Input) -> Output + Send + Sync>,
    ) {
        let mut db = self.state.write().unwrap();
        let route_entry = RouterEntry {
            router_data: Arc::new(RouterData { router_callback }),
        };
        db.request_routes.insert(route_key, route_entry);
    }

    pub fn add_response_message_route(
        &mut self,
        route_key: K,
        state_machine_type: MeshStateMachineType,
        router_callback: Box<
            dyn Fn(Result<Input, MeshError>, MeshStateMachineType, Context) -> Output + Send + Sync,
        >,
    ) {
        let mut db = self.state.write().unwrap();
        let route_entry = ResponseRouterEntry {
            router_data: Arc::new(ResponseRouterData { router_callback }),
        };
        db.response_states.insert(state_machine_type);
        db.response_routes
            .insert((route_key, state_machine_type), route_entry);
    }

    pub fn find_message_route(&self, route_key: &K) -> Option<Arc<RouterData<Input, Output>>> {
        let db = self.state.read().unwrap();
        let entry = db.request_routes.get(route_key);
        if let Some(entry) = entry {
            return Some(entry.router_data.clone());
        }
        return None;
    }

    pub fn find_response_message_route(
        &self,
        route_key: K,
        state_machine_type: MeshStateMachineType,
    ) -> Option<Arc<ResponseRouterData<Input, Output, Context>>> {
        let db = self.state.read().unwrap();
        let entry = db.response_routes.get(&(route_key, state_machine_type));
        if let Some(entry) = entry {
            return Some(entry.router_data.clone());
        }
        return None;
    }

    pub fn get_response_states(&self) -> HashSet<MeshStateMachineType> {
        let db = self.state.read().unwrap();
        return db.response_states.clone();
    }
}
