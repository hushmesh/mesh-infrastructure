use alloc::vec::Vec;

use num_derive::FromPrimitive;
use serde::Deserialize;
use serde::Serialize;

use common_types::MeshId;
use common_types::MeshMessageId;
use common_types::MeshSessionId;

use crate::MeshMessage;
use crate::MeshMessageType;
use crate::MeshSubsystem;

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum MaintenanceMessageType {
    Unknown = 0,
    ShutdownType = 1,
    ReadyForBootstrapType = 2,
    GetInitMessagesType = 3,
    BootstrapCompleteType = 4,
}

impl From<MaintenanceMessageType> for MeshMessageType {
    fn from(message_type: MaintenanceMessageType) -> MeshMessageType {
        message_type as u16
    }
}

macro_rules! impl_build_message {
    ($type:ident, $msgtype:ident, $app_handler:literal) => {
        pub struct $type(());

        impl $type {
            pub fn build_message(enclave_id: MeshId) -> MeshMessage {
                MeshMessage::build_app_enclave_message(
                    MeshMessageId::empty(),
                    enclave_id,
                    MeshSessionId::empty(),
                    MeshSubsystem::Maintenance,
                    MaintenanceMessageType::$msgtype.into(),
                    None::<Vec<u8>>,
                    $app_handler,
                    None,
                )
            }
        }
    };
}

impl_build_message!(ReadyForBootstrap, ReadyForBootstrapType, true);
impl_build_message!(GetInitMessages, GetInitMessagesType, false);
impl_build_message!(BootstrapComplete, BootstrapCompleteType, true);
