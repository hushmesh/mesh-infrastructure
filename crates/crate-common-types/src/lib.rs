//! Common types and functions

#[macro_use]
extern crate alloc;

/// actor manifest file used during build
pub mod actors_manifest;

/// common definitions used by agent trustee and entity trustee messages
pub mod agent_entity_trustee_objects;

/// Function for cbor
pub mod cbor;

/// macros for converting messages
pub mod convert_macros;

/// File directory functions
pub mod file_directories;

/// Functions for converting rust type to/from C types
pub mod from_c;

// common definitions used used by messages for image objects
pub mod image_data_objects;

/// common macros
pub mod macros;

/// function for getting name of node service is running on
pub mod node_name;

/// common definitions for permission names
pub mod permissions;

/// common definitions for relationship names
pub mod relationships;

/// common definitions for status messages
pub mod status_message_strings;

/// common definitions for getting time in enclave
pub mod time;

/// common definitions for uns data objects
pub mod uns_data_objects;

/// functions for validating data received in requests
pub mod validation;

/// common definitions for verifiable credentials data objects used in messages
pub mod verifiable_credentials_data_objects;

/// Definitions for version numbers stored for agents and trustees
pub mod versioning;

mod mesh_id;

use alloc::string::String;
use alloc::vec::Vec;
use core::error::Error;
use core::fmt;
use core::str::FromStr;

use log::error;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::Deserialize;
use serde::Serialize;

pub use crate::mesh_id::MeshId;

// object ids are not necessarily 32 bytes
// The may be used for things such as identifying an element in a list such as a list of
// messages.
pub type ObjectIdBytes = Vec<u8>;

pub type MeshLinkKey = MeshId;
pub type MeshSessionId = MeshId;
pub type MeshMessageId = MeshId;
pub type MeshCellNumber = MeshId;
pub type MeshNetworkId = MeshId;
pub type MeshStemCellKey = MeshId;
pub type MeshStemCellNumber = MeshCellNumber;
pub type MeshStemId = MeshId; // STID
pub type MeshPrivateId = MeshId; // PID
pub type MeshTrusteeId = MeshId;
pub type MeshAgentId = MeshId;
pub type MeshApplicationId = MeshId;
pub type MeshEntityKeychainStemId = MeshStemId; // ESTID
pub type MeshEntityKeychainId = MeshId; // EKID
pub type MeshEntityKeychainPrivateId = MeshPrivateId; // EPID
pub type MeshEntityKeychainNetworkId = MeshNetworkId; // ENID
pub type MeshEntityKeychainMeshId = MeshId; // EMID
pub type LinkedEntityKeychainMeshId = MeshId; // LEMID
pub type AgentLinkedEntityKeychainMeshId = MeshId; // ALEMID
pub type MeshExternalId = MeshId;
pub type MeshCellKey = MeshId;
pub type MeshEncryptionKey = MeshId;
pub type MeshLinkCode = MeshId;
pub type MeshObjectId = MeshId;
pub type ContextId = u64;
pub type MeshEntityType = u16;

pub type MeshPermission = String;
pub type MeshRelationship = String;

pub const MESHFA_CODE_EXPIRATION_TIME: i64 = 300000;
pub const DEFAULT_MESH_ENTITY_TYPE: MeshEntityType = 0;
pub const MESH_SHORT_URL: &str = "https://m.sh";

pub type DateString = String;

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct MeshCellKeyInfo {
    pub key: MeshCellKey,
    pub key_version: i32,

    // for encrypting key path
    #[serde(skip)]
    pub root_key: Option<MeshCellKey>,
    #[serde(skip)]
    pub parts: Option<Vec<Vec<u8>>>,
    pub is_stem_cell_key: bool,
}

#[derive(PartialEq, Debug, Copy, Clone, Serialize, Deserialize)]
pub enum UnsEntryType {
    Agent,
    Trustee,
    Guardian,
    Website,
}

#[derive(Eq, PartialEq, Clone, Copy, Debug, Serialize, Deserialize)]
pub enum TrusteeType {
    Global,
    Mesh,
    Root,
    Intermediate,
    Crew,
    Agent,
    Entity,
}

#[derive(
    Default, PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize,
)]
pub enum MeshDataFormat {
    #[default]
    None = 0,
    Cbor = 1,
    Opaque = 2,
    MeshId = 3,
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum ListenerType {
    Tcp = 0,
    Udp = 1,
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum ConnectorType {
    Tcp = 0,
    File = 1,
    Database = 2,
    BlobStorage = 3,
    Containers = 4,
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum MeshEncryptionType {
    None = 0,
    AesGcmNoPadding = 1,
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum QRCodeFormatType {
    None = 0,
    Svg = 1,
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum MeshSignatureType {
    None = 0,
    Ecdsa = 1,
    Hmac256 = 2,
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum MeshPublicKeyType {
    None = 0,
    Secp256r1 = 1,
    Secp384r1 = 2,
}

#[derive(
    PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize, Ord, PartialOrd,
)]
pub enum AuthenticationChallengeType {
    Unknown = 0,
    EmailOTP = 1,
    PhoneOTP = 2,
    PhoneNumber = 3,
    Secret = 4,
    EmailAddress = 5,
    PickAnotherEmailOrPhone = 6,
    CreateSecret = 7,
    PickEmailLinkedToHuman = 8,
    PickPhoneLinkedToHuman = 9,
    EnterMeshFACode = 10,
}

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct MeshAgentIdAndEntityType {
    pub agent_id: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_type: Option<MeshEntityType>,
}

impl From<MeshAgentIdAndEntityType> for Vec<u8> {
    fn from(id: MeshAgentIdAndEntityType) -> Vec<u8> {
        let entity_type = id.entity_type.unwrap_or(DEFAULT_MESH_ENTITY_TYPE);
        id.agent_id
            .id
            .iter()
            .copied()
            .chain(entity_type.to_be_bytes())
            .collect()
    }
}

pub fn entity_type_to_bytes(entity_type: MeshEntityType) -> Vec<u8> {
    entity_type.to_be_bytes().to_vec()
}

pub fn bytes_to_entity_type(val: &[u8]) -> MeshEntityType {
    if val.len() < 2 {
        return DEFAULT_MESH_ENTITY_TYPE;
    }
    u16::from_be_bytes([val[0], val[1]])
}

pub fn mesh_entity_type_or_default(entity_type: Option<MeshEntityType>) -> MeshEntityType {
    entity_type.unwrap_or(DEFAULT_MESH_ENTITY_TYPE)
}

#[derive(
    PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize,
)]
pub enum MeshLinkAttributesType {
    Unknown = 0,
    CanSendNotifications = 1,
    IsHumanMeshAdmin = 2, // until we have orgs
}

#[derive(
    PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize,
)]
pub enum NotificationType {
    Unknown = 0,
    SpaceInvite = 1,
    MeshFA,
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum MeshLinkAttributesOp {
    And = 0, // only and supoorted for now
}

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct MeshLinkAttributesTypeAndOp {
    pub attribute_type: MeshLinkAttributesType,
    pub attribute_op: MeshLinkAttributesOp,
}

impl MeshLinkAttributesTypeAndOp {
    pub fn new(attribute_type: MeshLinkAttributesType) -> MeshLinkAttributesTypeAndOp {
        MeshLinkAttributesTypeAndOp {
            attribute_type,
            attribute_op: MeshLinkAttributesOp::And,
        }
    }
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum MeshOSType {
    Unknown = 0,
    MacOS = 1,
    IOS = 2,
    Android = 3,
    Windows = 4,
    Linux = 5,
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum MeshClientType {
    Unknown = 0,
    Browser = 1,
    Mobile = 2,
    Desktop = 3,
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum MeshStatusType {
    Success = 0,
    ServerError = 1,
    SessionDoesNotExist = 2,
    InvalidCredentials = 3,
    AdditionalChallengesRequired = 4,
    BadRequest = 5,
    NotFound = 6,
    Unauthorized = 7,
    Conflict = 8,
    RateLimited = 9,
    NotReady = 10,
    Timeout = 11,
    InvalidSignature = 12,
    AlreadyDone = 13,
    DatabaseDuplicateKey = 14,
    NotConfirmed = 15,
    InvalidLinkKey = 16,
    AttestationFailure = 17,
    HasErrorListField = 18,
    RequestDenied = 19,
    DatabaseConcurrentUpdate = 20,
    InProgress = 21,
}

impl fmt::Display for MeshStatusType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl MeshStatusType {
    pub fn as_str(self) -> &'static str {
        match self {
            MeshStatusType::Success => "Success",
            MeshStatusType::ServerError => "Server error",
            MeshStatusType::SessionDoesNotExist => "Session does not exist",
            MeshStatusType::InvalidCredentials => "Invalid credentials",
            MeshStatusType::AdditionalChallengesRequired => "Additional challenges required",
            MeshStatusType::BadRequest => "Bad Request",
            MeshStatusType::NotFound => "Not found",
            MeshStatusType::AlreadyDone => "Already set",
            MeshStatusType::NotConfirmed => "Not confirmed",
            MeshStatusType::Unauthorized => "Unauthorized",
            MeshStatusType::RequestDenied => "Request denied",
            MeshStatusType::Conflict => "Conflict",
            MeshStatusType::RateLimited => "Rate limited",
            MeshStatusType::NotReady => "Not ready",
            MeshStatusType::Timeout => "Timeout",
            MeshStatusType::InProgress => "In progress",
            MeshStatusType::InvalidSignature => "Invalid signature",
            MeshStatusType::InvalidLinkKey => "Invalid link key",
            MeshStatusType::DatabaseDuplicateKey => "Database duplicate key",
            MeshStatusType::DatabaseConcurrentUpdate => "Database concurrent update",
            MeshStatusType::AttestationFailure => "Attestation failure",
            MeshStatusType::HasErrorListField => "Has error list field",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshInstanceRoute {
    pub fqdn: String,
    pub port: u16,
}

impl MeshInstanceRoute {
    pub fn get_endpoint(&self) -> String {
        format!("https://{}:{}/api", self.fqdn, self.port)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshRoute {
    pub fqdn: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_port: Option<u16>,
    #[serde(default, skip_serializing_if = "<&bool as core::ops::Not>::not")]
    pub needs_http_redirector: bool,
}

impl MeshRoute {
    pub fn get_endpoint(&self) -> String {
        format!("https://{}:{}/api", self.fqdn, self.port)
    }
    pub fn increase_port(&mut self, offset: u16) {
        self.port = self
            .port
            .checked_add(offset)
            .expect("PORT_OVERRIDE_OFFSET caused overflow");
        if let Some(container_port) = &mut self.container_port {
            *container_port = container_port
                .checked_add(offset)
                .expect("PORT_OVERRIDE_OFFSET caused overflow");
        }
    }
    pub fn new(fqdn: impl Into<String>, port: u16, container_port: Option<u16>) -> MeshRoute {
        MeshRoute {
            fqdn: fqdn.into(),
            port,
            container_port,
            needs_http_redirector: false,
        }
    }

    pub fn new_with_container_port(
        fqdn: impl Into<String>,
        port: u16,
        container_port: u16,
    ) -> MeshRoute {
        MeshRoute {
            fqdn: fqdn.into(),
            port,
            container_port: Some(container_port),
            needs_http_redirector: false,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum MeshError {
    DatabaseError(String),
    ParseError(String),
    IOError(String),
    ConnectError(String),
    SGXError(String),
    TLSError(String),
    ProtocolError(String),
    FileError(String),
    ChannelError(String),
    TimeoutError,
    SendError,
    InvalidAddress(String),
    NotSupported,
    IncompleteFrame,
    InsufficientResources,
    NoHandler,
    NoEnclave,
    NoListener,
    NoConnector,
    NoSender,
    NoConnection,
    NoRequest,
    EnclaveExists,
    EntityExists,
    NoSession,
    NotFound,
    AlreadyDone,
    NotConfirmed,
    MissingCellData,
    BadState,
    CannotDeletePrimary,
    NoParent,
    Unauthorized,
    InvalidJWT,
    Uninitialized,
    BootstrapFailed(String),
    RouteFailed(String),
    RequestFailed(String),
    BadArgument(String),
    LocalAttestationFailure,
    RemoteAttestationFailure,
    BufferTooSmall,
    DatabaseConcurrentUpdate,
    DatabaseDuplicateKey,
    EncryptionError(String),
    ThirdPartyError(String),
    EmailError(String),
    RateLimited(i64),
    InvalidLinkKey,
    InvalidMethod,
    PathElementConflict,
    NotReady,
    HasErrorListField,
    OutOfDate,
    InProgress,
    RequestDenied,
    TooManyPending,
}

impl Error for MeshError {}

impl fmt::Display for MeshError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MeshError::BadArgument(msg) => write!(f, "Bad Argument {}", msg),
            MeshError::BootstrapFailed(msg) => write!(f, "Bootstrap Failed {}", msg),
            MeshError::RouteFailed(msg) => write!(f, "Route Failed {}", msg),
            MeshError::RequestFailed(msg) => write!(f, "Request Failed {}", msg),
            MeshError::DatabaseError(msg) => write!(f, "Database Error {}", msg),
            MeshError::ThirdPartyError(msg) => write!(f, "Thirdparty Error {}", msg),
            MeshError::EmailError(msg) => write!(f, "Email Error {}", msg),
            MeshError::ParseError(msg) => write!(f, "Parse Error {}", msg),
            MeshError::IOError(msg) => write!(f, "IO Error {}", msg),
            MeshError::ConnectError(msg) => write!(f, "Connect Error {}", msg),
            MeshError::SGXError(msg) => write!(f, "SGX Error {}", msg),
            MeshError::TLSError(msg) => write!(f, "TLS Error {}", msg),
            MeshError::ProtocolError(msg) => write!(f, "Protocol Error {}", msg),
            MeshError::FileError(msg) => write!(f, "File Error {}", msg),
            MeshError::ChannelError(msg) => write!(f, "Channel Error {}", msg),
            MeshError::TimeoutError => write!(f, "Timeout error"),
            MeshError::SendError => write!(f, "Send Error"),
            MeshError::InvalidAddress(msg) => write!(f, "Invalid Address {}", msg),
            MeshError::NotSupported => write!(f, "Not supported"),
            MeshError::Unauthorized => write!(f, "Unauthorized"),
            MeshError::RequestDenied => write!(f, "Request Denied"),
            MeshError::InvalidJWT => write!(f, "Invalid JWT"),
            MeshError::Uninitialized => write!(f, "Uninitialized"),
            MeshError::InsufficientResources => write!(f, "Insufficient resources"),
            MeshError::NoParent => write!(f, "No parent"),
            MeshError::NoHandler => write!(f, "No handler configured"),
            MeshError::OutOfDate => write!(f, "Data is Out of data"),
            MeshError::InProgress => write!(f, "In Progress"),
            MeshError::CannotDeletePrimary => write!(f, "Cannot delete primary"),
            MeshError::NoEnclave => write!(f, "No enclave configured"),
            MeshError::NoListener => write!(f, "No listener configured"),
            MeshError::NoConnector => write!(f, "No connector configured"),
            MeshError::NoSender => write!(f, "No sender configured"),
            MeshError::NoConnection => write!(f, "No connection found"),
            MeshError::NoRequest => write!(f, "No request found"),
            MeshError::RateLimited(delay) => write!(f, "Rate limited, [delay={}]", delay),
            MeshError::NoSession => write!(f, "No session found"),
            MeshError::NotFound => write!(f, "Not found"),
            MeshError::AlreadyDone => write!(f, "Already done"),
            MeshError::NotConfirmed => write!(f, "Not confirmed"),
            MeshError::MissingCellData => write!(f, "Missing cell data"),
            MeshError::BadState => write!(f, "Bad state"),
            MeshError::BufferTooSmall => write!(f, "Buffer too small"),
            MeshError::LocalAttestationFailure => write!(f, "Local attestation failure"),
            MeshError::RemoteAttestationFailure => write!(f, "Remote attestation failure"),
            MeshError::EnclaveExists => write!(f, "Enclave exists"),
            MeshError::EntityExists => write!(f, "Entity exists"),
            MeshError::IncompleteFrame => write!(f, "Incomplete frame"),
            MeshError::DatabaseConcurrentUpdate => write!(f, "Concurrent update"),
            MeshError::DatabaseDuplicateKey => write!(f, "Duplicate key"),
            MeshError::InvalidLinkKey => write!(f, "Invalid link key"),
            MeshError::NotReady => write!(f, "Not ready"),
            MeshError::TooManyPending => write!(f, "Too many pending"),
            MeshError::InvalidMethod => write!(f, "Invalid method"),
            MeshError::PathElementConflict => write!(f, "Path element conflict"),
            MeshError::EncryptionError(msg) => write!(f, "Encryption error {}", msg),
            MeshError::HasErrorListField => write!(f, "Has error list field"),
        }
    }
}

impl From<u32> for ListenerType {
    fn from(val: u32) -> ListenerType {
        FromPrimitive::from_u32(val).unwrap_or_else(|| {
            error!("Unknown listener type {val}");
            ListenerType::Tcp
        })
    }
}

impl From<u32> for ConnectorType {
    fn from(val: u32) -> ConnectorType {
        FromPrimitive::from_u32(val).unwrap_or_else(|| {
            error!("Unknown connector type {val}");
            ConnectorType::Tcp
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct ConfigOptions {
    // allows an actor to be started in different configurations
    pub variant_type: u8,
    // allows the actor to be shutdown using the shutdown command
    pub shutdown: bool,
}

impl ConfigOptions {
    pub fn empty() -> ConfigOptions {
        ConfigOptions {
            variant_type: 0,
            shutdown: false,
        }
    }
}

pub fn i64_to_object_id(num: i64) -> ObjectIdBytes {
    let bytes = num.to_le_bytes();
    let mut size = 8;
    for i in (1..8).rev() {
        if bytes[i] == 0 {
            size -= 1;
        } else {
            break;
        }
    }

    bytes[..size].to_vec()
}

pub fn u64_to_object_id(num: u64) -> ObjectIdBytes {
    i64_to_object_id(num as i64)
}

pub fn object_id_to_u64<B: AsRef<[u8]>>(bytes: B) -> u64 {
    object_id_to_i64(bytes) as u64
}

pub fn object_id_to_i64<B: AsRef<[u8]>>(bytes: B) -> i64 {
    let bytes = bytes.as_ref();
    let mut array: [u8; 8] = [0; 8];
    let size = bytes.len().min(8);
    array[..size].copy_from_slice(&bytes[..size]);
    i64::from_le_bytes(array)
}

pub fn i64_and_i8_to_object_id(num: i64, num2: i8) -> ObjectIdBytes {
    let num = (num << 8) | (num2 as i64);
    i64_to_object_id(num)
}

pub fn object_id_to_i64_and_i8(bytes: Vec<u8>) -> (i64, i8) {
    let val = object_id_to_i64(bytes);
    let num2 = (val & 0xff) as i8;
    let num = val >> 8;
    (num, num2)
}

pub enum ContextIdCounterSubsystem {
    Metrics = 0,
    HttpsListener = 1,
    FactoryInternal = 2,
}

pub struct ContextIdCounter {
    pub counter: ContextId,
    pub subsystem: u8,
}

impl ContextIdCounter {
    pub fn new(subsystem: ContextIdCounterSubsystem) -> ContextIdCounter {
        ContextIdCounter {
            counter: 0,
            subsystem: subsystem as u8,
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> ContextId {
        let context_id = self.counter;
        self.counter += 1;
        if self.counter >= 0xffff_ffff_ffff {
            self.counter = 0;
        }
        context_id | ((self.subsystem as ContextId) << 48)
    }
}

// Parses an unsigned int, but only allows the normal form.  Ie, "+0001" is not allowed.
pub fn strict_uint<T>(s: &str) -> Option<T>
where
    T: From<u8> + FromStr + num_traits::sign::Unsigned,
{
    match s.as_bytes() {
        [] => None,
        [b @ b'0'..=b'9'] => Some((b - b'0').into()),
        [b'1'..=b'9', ..] => s.parse().ok(),
        _ => None,
    }
}

/// Panics if input.len() != N * 2.
pub const fn hex_array<const N: usize>(input: &str) -> [u8; N] {
    const fn digit(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'A'..=b'F' => b - b'A' + 10,
            b'a'..=b'f' => b - b'a' + 10,
            _ => panic!("invalid hex digit"),
        }
    }

    if input.len() < N * 2 {
        panic!("input is too short");
    } else if input.len() > N * 2 {
        panic!("input is too long");
    }

    let input = input.as_bytes();

    let mut i = 0;
    let mut out = [0u8; N];
    loop {
        if i >= N {
            // Safety: we've initialized `out`.
            return out;
        }
        out[i] = (digit(input[2 * i]) << 4) + digit(input[2 * i + 1]);
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_i64_to_object_id() {
        assert_eq!(i64_to_object_id(0), vec![0]);
        assert_eq!(i64_to_object_id(1), vec![1]);
        assert_eq!(i64_to_object_id(0xF0000000F), vec![15, 0, 0, 0, 15]);
        assert_eq!(i64_to_object_id(0xFFFFFFFFF), vec![255, 255, 255, 255, 15]);
        assert_eq!(i64_to_object_id(-1), vec![255; 8]);
        assert_eq!(i64_to_object_id(i64::MIN), vec![0, 0, 0, 0, 0, 0, 0, 128]);
        assert_eq!(i64_to_object_id(128), vec![128]);
    }

    #[test]
    fn test_object_id_to_i64() {
        assert_eq!(object_id_to_i64(vec![0]), 0);
        assert_eq!(object_id_to_i64(vec![1]), 1);
        assert_eq!(object_id_to_i64(vec![15, 0, 0, 0, 15]), 0xF0000000F);
        assert_eq!(object_id_to_i64(vec![255, 255, 255, 255, 15]), 0xFFFFFFFFF);
        assert_eq!(object_id_to_i64(vec![255; 8]), -1);
        assert_eq!(object_id_to_i64(vec![0, 0, 0, 0, 0, 0, 0, 128]), i64::MIN);
        assert_eq!(object_id_to_i64(vec![128]), 128);
    }

    #[test]
    fn test_agentid_and_entity_to_vec() {
        let id = (1..=32).collect::<Vec<u8>>().try_into().unwrap();
        let entity_type = Some(0xffee);
        let maiaet = MeshAgentIdAndEntityType {
            agent_id: MeshId { id },
            entity_type,
        };
        let out: Vec<u8> = maiaet.into();
        assert_eq!(
            &out,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32, 0xff, 0xee
            ],
        )
    }

    #[test]
    fn test_strict_uint() {
        assert_eq!(0u16, strict_uint::<u16>("0").unwrap());
        assert_eq!(1u32, strict_uint::<u32>("1").unwrap());
        assert_eq!(10u64, strict_uint::<u64>("10").unwrap());
        assert_eq!(100u8, strict_uint::<u8>("100").unwrap());

        assert!(strict_uint::<u16>("+1").is_none());
        assert!(strict_uint::<u32>("01").is_none());
        assert!(strict_uint::<u64>("+01").is_none());
    }
}
