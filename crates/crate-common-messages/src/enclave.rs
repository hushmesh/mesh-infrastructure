use alloc::string::String;
use alloc::vec::Vec;

use dyn_clone::clone_trait_object;
use dyn_clone::DynClone;

use common_build_injection::MeshIdentificationData;
use common_types::MeshError;
use common_types::MeshSessionId;

use crate::MeshMessage;
use crate::MeshMessageRef;

pub trait EnclaveFunction: Send + DynClone {
    fn process<'c>(
        &mut self,
        message: MeshMessageRef<'c>,
    ) -> Result<(Vec<MeshMessageRef<'c>>, Option<i64>), MeshError>;
    fn get_identification(&self) -> MeshIdentificationData;
    fn get_init_messages(&self) -> Result<Vec<MeshMessage>, MeshError>;
    fn process_timer(&self) -> Result<(Vec<MeshMessage>, Option<i64>), MeshError>;
}
clone_trait_object!(EnclaveFunction);

pub trait EnclaveListenerInterface: Send + DynClone + EnclaveFunction {
    fn new_connection(
        &self,
        peer_ip: String,
    ) -> Result<(MeshSessionId, Vec<MeshMessage>), MeshError>;
    fn drop_connection(&self, session_id: MeshSessionId) -> Result<Vec<MeshMessage>, MeshError>;
}
clone_trait_object!(EnclaveListenerInterface);

pub trait EnclaveConnectorInterface: Send + DynClone + EnclaveFunction {
    fn drop_connection(
        &self,
        session_id: MeshSessionId,
        client_closed: bool,
    ) -> Result<Vec<MeshMessage>, MeshError>;
}
clone_trait_object!(EnclaveConnectorInterface);
