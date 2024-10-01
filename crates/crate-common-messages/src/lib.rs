//! Message definitions

#![allow(clippy::too_many_arguments)]
#![cfg_attr(feature = "enclave", no_std)]

#[macro_use]
extern crate alloc;

use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use log::error;
use num::FromPrimitive;
use num_derive::FromPrimitive;
use regex::Regex;
use serde::Deserialize;
use serde::Serialize;

use common_crypto::constant_time_eq;
use common_crypto::mesh_decrypt;
use common_crypto::mesh_encrypt;
use common_crypto::HmacSha256Writer;
use common_crypto::HmcDataType;
use common_types::cbor::to_vec_packed;
use common_types::log_error;
use common_types::ContextId;
use common_types::MeshEncryptionType;
use common_types::MeshEntityType;
use common_types::MeshError;
use common_types::MeshId;
use common_types::MeshLinkAttributesTypeAndOp;
use common_types::MeshLinkCode;
use common_types::MeshMessageId;
use common_types::MeshSessionId;
use common_types::MeshSignatureType;
use common_types::MeshStatusType;

use crate::agent_messages::AgentMessageType;
use crate::agent_trustee_messages::AgentTrusteeMessageType;
use crate::certificate_agent_messages::CertificateAgentMessageType;
use crate::entity_trustee_messages::EntityTrusteeMessageType;
use crate::maintenance_messages::MaintenanceMessageType;
use crate::message_types::HttpsClientMessageType;
use crate::message_types::HttpsListenerMessageType;
use crate::message_types::WebsocketListenerMessageType;
use crate::metrics_messages::MetricsMessageType;
use crate::wrapped_message::WrappedMessage;

/// Messages sent to agents
pub mod agent_messages;

/// Messages sent to agent trustees
pub mod agent_trustee_messages;

/// Messages sent to certificate agent
pub mod certificate_agent_messages;

/// Traits to define message handling functions of an enclave
pub mod enclave;

/// Messages sent to entity trustees
pub mod entity_trustee_messages;

/// Messages used for maintenance handling
pub mod maintenance_messages;

/// Message types for the various messages
pub mod message_types;

/// Messages for handling metrics
pub mod metrics_messages;

/// Message type for wrapping a message in another
pub mod wrapped_message;

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum MeshSubsystem {
    Unknown = 0,
    MeshIn = 1,
    FileCache = 2,
    WebsocketClient = 3,
    LocalAttestation = 4,
    Connector = 5,
    Listener = 6,
    HttpsClient = 7,
    CertificateAgent = 8,
    Database = 9,
    NetworkTrust = 10,
    WebsocketListener = 11,
    UNS = 12,
    Guardian = 13,
    AgentTrustee = 14,
    EntityTrustee = 15,
    Agent = 16,
    Maintenance = 17,
    RemoteAttestation = 18,
    AuthenticationAgent = 19,
    EmailAgent = 20,
    PhoneAgent = 21,
    HumanProxyAgent = 22,
    HumanAgent = 23,
    OrganizationAgent = 24,
    ApplicationAgent = 25,
    HttpsListener = 26,
    OIDCAgent = 27,
    BlobStorage = 28,
    FileSystemAgent = 29,
    Metrics = 30,
    DeploymentAgent = 31,
    Container = 32,
    MeshInInternal = 33,
    FactoryAgent = 34,
    AgentDelegate = 35,
    AgentConfiguration = 36,
    FileSystemAgentClient = 37,
    WebsocketFrames = 38,
    HumanAgentInternal = 39,
    SpaceAgent = 40,
    UdpListener = 41,
    VCHolderAgent = 42,
    VDRAgent = 43,
    HSMECDSAAgent = 44,
    HSMBBSAgent = 45,
    WeblinkAgent = 46,
    DomainAgent = 47,
    DomainAgentClient = 48,
    OrgMemberAgent = 49,
    PersonaAgent = 50,
}
pub type MeshMessageType = u16;

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum DatastoreColumnType {
    Bool(Option<bool>),
    Int(Option<i32>),
    BigInt(Option<i64>),
    SmallInt(Option<i16>),
    Float(Option<f64>),
    Text(Option<String>),
    Binary(Option<Vec<u8>>),
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum DatastoreParameterType {
    Bool(Option<bool>),
    Int(Option<i32>),
    BigInt(Option<i64>),
    BigIntTimestamp(Option<i64>),
    SmallInt(Option<i16>),
    Float(Option<f64>),
    Text(Option<String>),
    Binary(Option<Vec<u8>>),
    BoolArray(Vec<bool>),
    IntArray(Vec<i32>),
    BigIntArray(Vec<i64>),
    SmallIntArray(Vec<i16>),
    FloatArray(Vec<f64>),
    TextArray(Vec<String>),
    BinaryArray(Vec<Vec<u8>>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshMessageRoutingLocalInternal {
    pub source_enclave: MeshId,
    pub destination_enclave: MeshId,
    pub transport_session_id: MeshSessionId,
    pub app_handler: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_type: Option<MeshEncryptionType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshMessageHeader {
    pub destination: MeshId,
    pub subsystem: MeshSubsystem,
    pub message_type: MeshMessageType,
    pub message_id: MeshMessageId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_session_id: Option<MeshSessionId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_type: Option<MeshEncryptionType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_type: Option<MeshSignatureType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<MeshStatusType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<MeshId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<Vec<MeshId>>,
    // only set if sending to different process
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub metrics: Option<Vec<u8>>,
    // for tracing
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<ContextId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshMessageRef<'c> {
    pub header: MeshMessageHeader,
    #[serde(
        borrow,
        default,
        with = "serde_bytes",
        skip_serializing_if = "Option::is_none"
    )]
    pub payload: Option<Cow<'c, [u8]>>,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_internal: Option<MeshMessageRoutingLocalInternal>, // only send between enclaves, not between mesh processes
}

pub type MeshMessage = MeshMessageRef<'static>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshMessageList<'c> {
    #[serde(borrow)]
    pub messages: Vec<MeshMessageRef<'c>>,
}

impl<'c> MeshMessageRef<'c> {
    pub fn build_app_enclave_message(
        message_id: MeshMessageId,
        enclave_mesh_id: MeshId,
        transport_session_id: MeshSessionId,
        subsystem: MeshSubsystem,
        message_type: MeshMessageType,
        payload: Option<impl Into<Cow<'c, [u8]>>>,
        app_handler: bool,
        context_id: Option<ContextId>,
    ) -> Self {
        let mut message = Self::build_request(
            enclave_mesh_id,
            enclave_mesh_id,
            subsystem,
            message_type,
            message_id,
            None,
            None,
            None,
            payload,
            context_id,
        );
        message.local_internal = Some(MeshMessageRoutingLocalInternal {
            source_enclave: enclave_mesh_id,
            destination_enclave: enclave_mesh_id,
            transport_session_id,
            encryption_type: None,
            app_handler,
            signature: None,
        });
        message
    }

    pub fn is_app_enclave_message(&self) -> bool {
        self.header.source.as_ref() == Some(&self.header.destination)
            && self.local_internal.as_ref().map_or(false, |internal| {
                internal.source_enclave == internal.destination_enclave
            })
    }

    pub fn build_request_for_transport(
        source: MeshId,
        destination: MeshId,
        subsystem: MeshSubsystem,
        message_type: MeshMessageType,
        message_id: MeshMessageId,
        link_session_id: Option<MeshSessionId>,
        encryption_type: Option<MeshEncryptionType>,
        signature_type: Option<MeshSignatureType>,
        payload: Option<Vec<u8>>,
        destination_enclave: MeshId,
        transport_session_id: MeshSessionId,
        context_id: Option<ContextId>,
    ) -> Self {
        let mut message = Self::build_request(
            source,
            destination,
            subsystem,
            message_type,
            message_id,
            link_session_id,
            encryption_type,
            signature_type,
            payload,
            context_id,
        );
        message.local_internal = Some(MeshMessageRoutingLocalInternal {
            source_enclave: source,
            destination_enclave,
            transport_session_id,
            encryption_type: None,
            app_handler: false,
            signature: None,
        });
        message
    }

    pub fn build_request(
        source: MeshId,
        destination: MeshId,
        subsystem: MeshSubsystem,
        message_type: MeshMessageType,
        message_id: MeshMessageId,
        link_session_id: Option<MeshSessionId>,
        encryption_type: Option<MeshEncryptionType>,
        signature_type: Option<MeshSignatureType>,
        payload: Option<impl Into<Cow<'c, [u8]>>>,
        context_id: Option<ContextId>,
    ) -> Self {
        Self {
            header: MeshMessageHeader {
                source: Some(source),
                destination,
                subsystem,
                message_type,
                message_id,
                link_session_id,
                encryption_type,
                signature_type,
                status: None,
                status_message: None,
                route: None,
                metrics: None,
                context_id,
            },
            payload: payload.map(Into::into),
            signature: None,
            local_internal: None,
        }
    }

    pub fn build_interenclave_message(
        source: MeshId,
        destination: MeshId,
        source_enclave: MeshId,
        destination_enclave: MeshId,
        subsystem: MeshSubsystem,
        message_type: MeshMessageType,
        message_id: MeshMessageId,
        payload: Option<impl Into<Cow<'c, [u8]>>>,
        transport_session_id: MeshId,
        context_id: Option<ContextId>,
    ) -> Self {
        let mut message = Self::build_request(
            source,
            destination,
            subsystem,
            message_type,
            message_id,
            None,
            None,
            None,
            payload,
            context_id,
        );
        message.local_internal = Some(MeshMessageRoutingLocalInternal {
            source_enclave,
            destination_enclave,
            transport_session_id,
            encryption_type: None,
            app_handler: false,
            signature: None,
        });
        message
    }

    pub fn build_interenclave_message_for_external_client(
        source_enclave: MeshId,
        destination_enclave: MeshId,
        subsystem: MeshSubsystem,
        message_type: MeshMessageType,
        message_id: MeshMessageId,
        payload: Option<impl Into<Cow<'c, [u8]>>>,
        transport_session_id: MeshId,
        link_session_id: MeshId,
        status: Option<MeshStatusType>,
        status_message: Option<String>,
        context_id: Option<ContextId>,
    ) -> Self {
        let mut message = Self::build_interenclave_message(
            MeshId::empty(),
            MeshId::empty(),
            source_enclave,
            destination_enclave,
            subsystem,
            message_type,
            message_id,
            payload,
            transport_session_id,
            context_id,
        );
        message.header.link_session_id = Some(link_session_id);
        message.header.status = status;
        message.header.status_message = status_message;
        message.header.source = None;
        message
    }

    pub fn payload_len(&self) -> usize {
        self.payload.as_deref().map_or(0, <[_]>::len)
    }

    pub fn get_transport_session_id_or_none(&self) -> Option<MeshSessionId> {
        self.local_internal
            .as_ref()
            .map(|internal| internal.transport_session_id)
    }

    pub fn get_transport_session_id_or_error(&self) -> Result<MeshSessionId, MeshError> {
        self.get_transport_session_id_or_none()
            .ok_or(MeshError::NoSession)
    }

    pub fn get_message_source(&self) -> Result<MeshId, MeshError> {
        self.header
            .source
            .ok_or_else(|| MeshError::RouteFailed("no message source".into()))
    }

    pub fn encrypt_and_add_signature(&mut self, key: MeshId) -> Result<(), MeshError> {
        self.encrypt_message(key, true)
    }

    pub fn encrypt(&mut self, key: MeshId) -> Result<(), MeshError> {
        self.encrypt_message(key, false)
    }

    fn encrypt_message(&mut self, key: MeshId, add_signature: bool) -> Result<(), MeshError> {
        if self.header.signature_type != Some(MeshSignatureType::Ecdsa) && add_signature {
            self.header.signature_type = Some(MeshSignatureType::Hmac256);
            self.signature = Some(self.build_signature(&key.id)?);
        }

        if let Some(payload) = &self.payload {
            let encrypted_payload =
                mesh_encrypt(HmcDataType::Raw, &key.id, payload, &[], HmcDataType::Raw)?;
            self.payload = Some(encrypted_payload.into());
        }

        Ok(())
    }

    pub fn build_local_internal_signature(&mut self, key: &[u8]) -> Result<Vec<u8>, MeshError> {
        let context_id = self.header.context_id.take();
        let metrics = self.header.metrics.take();
        let mut old_signature: Option<Vec<u8>> = None;
        let mut encryption_type: Option<MeshEncryptionType> = None;
        if let Some(internal) = self.local_internal.as_mut() {
            old_signature = internal.signature.take();
            encryption_type = internal.encryption_type.take();
        }

        let mut hmac = HmacSha256Writer::new(key)?;
        let mut ser = serde_cbor::ser::Serializer::new(&mut hmac).packed_format();
        <Self as Serialize>::serialize(self, &mut ser).unwrap();

        self.header.context_id = context_id;
        self.header.metrics = metrics;
        if let Some(internal) = self.local_internal.as_mut() {
            internal.signature = old_signature;
            internal.encryption_type = encryption_type;
        }
        Ok(hmac.finalize()?.to_vec())
    }

    pub fn validate_local_internal_signature(&mut self, key: &[u8]) -> Result<(), MeshError> {
        let signature_check = self.build_local_internal_signature(key)?;
        if let Some(internal) = &self.local_internal {
            if let Some(signature) = &internal.signature {
                if constant_time_eq(&signature_check, signature) {
                    return Ok(());
                } else {
                    error!(
                        "signature does not match {:?} {:?}",
                        signature_check, signature
                    );
                }
            }
        }
        Err(MeshError::EncryptionError("missing local signature".into()))
    }

    fn build_signature(&mut self, key: &[u8]) -> Result<Vec<u8>, MeshError> {
        let context_id = self.header.context_id.take();
        let metrics = self.header.metrics.take();
        let old_signature: Option<Vec<u8>> = self.signature.take();
        let local_internal = self.local_internal.take();

        let mut hmac = common_crypto::HmacSha256Writer::new(key)?;
        let mut ser = serde_cbor::ser::Serializer::new(&mut hmac).packed_format();
        <Self as Serialize>::serialize(self, &mut ser)
            .map_err(|e| MeshError::ParseError(format!("{}", e)))?;

        self.local_internal = local_internal;
        self.header.context_id = context_id;
        self.header.metrics = metrics;
        self.signature = old_signature;
        Ok(hmac.finalize()?.to_vec())
    }

    fn validate_signature(&mut self, key: &[u8], signature: &[u8]) -> Result<(), MeshError> {
        let signature_check = self.build_signature(key)?;
        if !constant_time_eq(&signature_check, signature) {
            return Err(MeshError::EncryptionError("invalid signature".into()));
        }
        Ok(())
    }

    pub fn decrypt(&mut self, key: MeshId) -> Result<(), MeshError> {
        self.decrypt_internal(key, false)
    }

    pub fn decrypt_signature_required(&mut self, key: MeshId) -> Result<(), MeshError> {
        self.decrypt_internal(key, true)
    }

    fn decrypt_internal(&mut self, key: MeshId, signature_required: bool) -> Result<(), MeshError> {
        if let Some(payload) = self.payload.as_deref() {
            let decrypted_payload = mesh_decrypt(
                HmcDataType::Raw,
                &key.id,
                HmcDataType::Raw,
                payload,
                &[],
                HmcDataType::Raw,
            )?;
            self.payload = Some(decrypted_payload.into());
        }
        if signature_required {
            let signature = self
                .signature
                .take()
                .ok_or_else(|| MeshError::EncryptionError("no signature found".into()))?;
            let res = self.validate_signature(&key.id, &signature);
            self.signature = Some(signature);
            res
        } else {
            Ok(())
        }
    }

    pub fn build_reply(
        &self,
        response_message_type: MeshMessageType,
        status: MeshStatusType,
        status_message: Option<String>,
        payload: Option<Vec<u8>>,
    ) -> MeshMessage {
        let destination = self.header.source.unwrap_or(MeshId::empty());
        let source = Some(self.header.destination);
        let mut new_internal: Option<MeshMessageRoutingLocalInternal> = None;
        if let Some(ref internal) = self.local_internal {
            let new_internal_routing = MeshMessageRoutingLocalInternal {
                transport_session_id: internal.transport_session_id,
                source_enclave: internal.destination_enclave,
                destination_enclave: internal.source_enclave,
                encryption_type: None,
                app_handler: false,
                signature: None,
            };
            new_internal = Some(new_internal_routing);
        }
        MeshMessage {
            header: MeshMessageHeader {
                destination,
                source,
                subsystem: self.header.subsystem,
                message_type: response_message_type,
                message_id: self.header.message_id,
                link_session_id: self.header.link_session_id,
                encryption_type: None,
                signature_type: None,
                status: Some(status),
                status_message,
                route: None,
                metrics: None,
                context_id: self.header.context_id,
            },
            payload: payload.map(Cow::Owned),
            signature: None,
            local_internal: new_internal,
        }
    }

    pub fn serialize(&mut self, internal: bool) -> Result<Vec<u8>, MeshError> {
        let mut internal_data: Option<MeshMessageRoutingLocalInternal> = None;
        if !internal {
            internal_data = self.local_internal.take();
        }
        let payload = to_vec_packed(self)?;
        if !internal {
            self.local_internal = internal_data;
        }
        Ok(payload)
    }

    pub fn unserialize(data: &'c [u8]) -> Result<Self, MeshError> {
        serde_cbor::from_slice(data).map_err(|e| MeshError::ParseError(e.to_string()))
    }

    /// Converts a MeshMessageRef<'c> (possibly borrowing from a `&'c [u8]` of CBOR data) to an
    /// owned, 'static MeshMessage. If the MeshMessageRef's payload was already Cow::Owned, this
    /// will be a no-op aside from the lifetime promotion.
    pub fn into_static(self) -> MeshMessage {
        let payload = self.payload.map(|p| Cow::Owned(p.into_owned()));
        MeshMessage { payload, ..self }
    }

    pub fn set_internal_source_destination(
        &mut self,
        source: MeshId,
        destination: MeshId,
        session_id: MeshSessionId,
    ) {
        if let Some(internal) = self.local_internal.as_mut() {
            internal.source_enclave = source;
            internal.destination_enclave = destination;
            internal.transport_session_id = session_id;
        } else {
            self.local_internal = Some(MeshMessageRoutingLocalInternal {
                source_enclave: source,
                destination_enclave: destination,
                transport_session_id: session_id,
                encryption_type: None,
                app_handler: false,
                signature: None,
            });
        }
    }

    pub fn get_internal_destination(&self) -> MeshId {
        match &self.local_internal {
            Some(internal) => internal.destination_enclave,
            None => self.header.destination,
        }
    }

    pub fn get_internal_destination_and_app_handler(&self) -> (MeshId, bool) {
        match &self.local_internal {
            Some(internal) => (internal.destination_enclave, internal.app_handler),
            None => (self.header.destination, false),
        }
    }

    pub fn get_internal_source(&self) -> MeshId {
        self.local_internal
            .as_ref()
            .map(|internal| internal.source_enclave)
            .unwrap_or(MeshId::empty())
    }

    pub fn is_success(&self) -> bool {
        self.header.status == Some(MeshStatusType::Success)
    }

    pub fn is_not_found(&self) -> bool {
        self.header.status == Some(MeshStatusType::NotFound)
    }

    pub fn is_duplicate_error(&self) -> bool {
        self.header.status == Some(MeshStatusType::DatabaseDuplicateKey)
    }

    pub fn is_success_or_has_error_list_field(&self) -> bool {
        matches!(
            self.header.status,
            Some(MeshStatusType::Success | MeshStatusType::HasErrorListField)
        )
    }

    pub fn error_reply(
        &self,
        message_type: MeshMessageType,
        status: MeshStatusType,
        status_text: String,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let response = self.build_reply(message_type, status, Some(status_text), None);
        Ok(vec![response])
    }

    pub fn empty() -> MeshMessage {
        let request = MeshMessage::build_request(
            MeshId::empty(),
            MeshId::empty(),
            MeshSubsystem::Unknown,
            0,
            MeshMessageId::empty(),
            None,
            None,
            None,
            None::<Vec<u8>>,
            None,
        );
        request.build_reply(0, MeshStatusType::Success, None, None)
    }

    pub fn get_context_id(&self) -> Option<ContextId> {
        self.header.context_id
    }

    pub fn clone_for_reply(&self) -> MeshMessage {
        MeshMessage {
            header: self.header.clone(),
            local_internal: self.local_internal.clone(),
            payload: None,
            signature: None,
        }
    }

    pub fn clone_borrow_payload(&self) -> MeshMessageRef<'_> {
        MeshMessageRef {
            header: self.header.clone(),
            local_internal: self.local_internal.clone(),
            payload: self.payload.as_deref().map(Cow::Borrowed),
            signature: None,
        }
    }

    pub fn clone_copy_payload(&self) -> MeshMessage {
        let payload = self.payload.as_ref().map(|p| Cow::Owned(p.to_vec()));
        MeshMessageRef {
            header: self.header.clone(),
            local_internal: self.local_internal.clone(),
            payload,
            signature: None,
        }
    }

    pub fn extract<'a, 'de, T>(&'a self) -> Result<T, MeshError>
    where
        'a: 'de,
        T: Deserialize<'de>,
    {
        let payload = self.payload.as_ref().ok_or_else(|| {
            log_error!(MeshError::ParseError("No payload in message".to_string()))
        })?;
        serde_cbor::from_slice(payload).map_err(|e| MeshError::ParseError(e.to_string()))
    }

    pub fn check_status(&self) -> Result<(), MeshError> {
        if self.is_success() {
            Ok(())
        } else {
            Err(message_header_to_error(self))
        }
    }

    pub fn check_status_not_found_ok(&self) -> Result<(), MeshError> {
        if self.is_success() || self.is_not_found() {
            Ok(())
        } else {
            Err(message_header_to_error(self))
        }
    }

    pub fn extract_check_status<'a, 'de, T>(&'a self) -> Result<T, MeshError>
    where
        'a: 'de,
        T: Deserialize<'de>,
    {
        self.check_status()?;
        self.extract()
    }
}

impl<'c> MeshMessageList<'c> {
    pub fn serialize(&self) -> Result<Vec<u8>, MeshError> {
        to_vec_packed(self)
    }

    pub fn unserialize(data: &'c [u8]) -> Result<Self, MeshError> {
        if data.is_empty() {
            Ok(MeshMessageList {
                messages: Vec::new(),
            })
        } else {
            serde_cbor::from_slice(data).map_err(|e| MeshError::ParseError(e.to_string()))
        }
    }

    pub fn into_static(self) -> MeshMessageList<'static> {
        let messages = self
            .messages
            .into_iter()
            .map(MeshMessageRef::into_static)
            .collect();
        MeshMessageList { messages }
    }
}

impl MeshMessageRoutingLocalInternal {
    pub fn new(
        transport_session_id: MeshId,
        source: MeshId,
        destination: MeshId,
        app_handler: bool,
    ) -> MeshMessageRoutingLocalInternal {
        MeshMessageRoutingLocalInternal {
            source_enclave: source,
            destination_enclave: destination,
            transport_session_id,
            encryption_type: None,
            app_handler,
            signature: None,
        }
    }
}

fn message_status_to_error(
    status: Option<MeshStatusType>,
    status_message: &Option<String>,
) -> MeshError {
    let status_message = match status_message {
        None => status.unwrap_or(MeshStatusType::Success).to_string(),
        Some(text) => text.clone(),
    };
    match status {
        None => MeshError::RequestFailed(status_message),
        Some(status) => match status {
            MeshStatusType::Timeout => MeshError::TimeoutError,
            MeshStatusType::NotFound => MeshError::NotFound,
            MeshStatusType::AlreadyDone => MeshError::AlreadyDone,
            MeshStatusType::NotConfirmed => MeshError::NotConfirmed,
            MeshStatusType::RateLimited => {
                let delay = extract_delay_from_rate_limit_error(&status_message);
                MeshError::RateLimited(delay.unwrap_or(0))
            }
            MeshStatusType::Conflict => MeshError::EntityExists,
            MeshStatusType::Unauthorized => MeshError::Unauthorized,
            MeshStatusType::InProgress => MeshError::InProgress,
            MeshStatusType::RequestDenied => MeshError::RequestDenied,
            MeshStatusType::InvalidLinkKey => MeshError::InvalidLinkKey,
            MeshStatusType::DatabaseDuplicateKey => MeshError::DatabaseDuplicateKey,
            MeshStatusType::DatabaseConcurrentUpdate => MeshError::DatabaseConcurrentUpdate,
            MeshStatusType::BadRequest => MeshError::BadArgument(
                status_message
                    .strip_prefix("Bad Request")
                    .unwrap_or(&status_message)
                    .trim()
                    .to_string(),
            ),
            _ => MeshError::RequestFailed(
                status_message
                    .strip_prefix("Request Failed")
                    .unwrap_or(&status_message)
                    .trim()
                    .to_string(),
            ),
        },
    }
}

pub fn agent_message_header_to_error(message: &WrappedMessage) -> MeshError {
    message_status_to_error(message.status, &message.status_message)
}

pub fn message_header_to_error(message: &MeshMessageRef) -> MeshError {
    message_status_to_error(message.header.status, &message.header.status_message)
}

pub fn error_to_message_header_status(
    err: &MeshError,
    default_message: Option<String>,
) -> (MeshStatusType, String) {
    let default_message = move || default_message.unwrap_or_else(|| err.to_string());
    match err {
        MeshError::TimeoutError => (MeshStatusType::Timeout, default_message()),
        MeshError::NotFound => (MeshStatusType::NotFound, default_message()),
        MeshError::AlreadyDone => (MeshStatusType::AlreadyDone, default_message()),
        MeshError::InProgress => (MeshStatusType::InProgress, default_message()),
        MeshError::NotConfirmed => (MeshStatusType::NotConfirmed, default_message()),
        MeshError::RateLimited(_) => (MeshStatusType::RateLimited, err.to_string()),
        MeshError::Unauthorized => (MeshStatusType::Unauthorized, default_message()),
        MeshError::RequestDenied => (MeshStatusType::RequestDenied, default_message()),
        MeshError::InvalidJWT => (MeshStatusType::Unauthorized, default_message()),
        MeshError::InvalidLinkKey => (MeshStatusType::InvalidLinkKey, default_message()),
        MeshError::CannotDeletePrimary => (MeshStatusType::Conflict, default_message()),
        MeshError::EntityExists => (MeshStatusType::Conflict, default_message()),
        MeshError::PathElementConflict => (MeshStatusType::Conflict, default_message()),
        MeshError::DatabaseDuplicateKey => {
            (MeshStatusType::DatabaseDuplicateKey, default_message())
        }
        MeshError::DatabaseConcurrentUpdate => {
            (MeshStatusType::DatabaseConcurrentUpdate, default_message())
        }
        MeshError::BadArgument(text) => (MeshStatusType::BadRequest, text.clone()),
        MeshError::HasErrorListField => (MeshStatusType::HasErrorListField, default_message()),
        MeshError::RemoteAttestationFailure => {
            (MeshStatusType::AttestationFailure, default_message())
        }
        MeshError::LocalAttestationFailure => {
            (MeshStatusType::AttestationFailure, default_message())
        }
        _ => (MeshStatusType::ServerError, default_message()),
    }
}

pub fn error_to_http_status(err: &MeshError) -> u16 {
    match err {
        MeshError::TimeoutError => 400,
        MeshError::NotFound => 404,
        MeshError::AlreadyDone => 304,
        MeshError::NotConfirmed => 401,
        MeshError::RateLimited(_) => 429,
        MeshError::Unauthorized => 401,
        MeshError::InvalidLinkKey => 401,
        MeshError::RequestDenied => 403,
        MeshError::CannotDeletePrimary => 409,
        MeshError::EntityExists => 409,
        MeshError::InProgress => 409,
        MeshError::DatabaseDuplicateKey => 500,
        MeshError::InvalidMethod => 405,
        MeshError::BadArgument(_) => 400,
        MeshError::ParseError(_) => 400,
        _ => 500,
    }
}

macro_rules! mesh_message_type_to_string {
    ($($variant:ident => $message_type:ty),* $(,)?) => {
        pub fn message_type_string(subsystem: MeshSubsystem, message_type: MeshMessageType) -> String {
            match subsystem {
                MeshSubsystem::Unknown => "Unknown".into(),
                $(
                    MeshSubsystem::$variant => format!(
                        "{:?}",
                        FromPrimitive::from_u16(message_type).unwrap_or(<$message_type>::Unknown)
                    ),
                )*
                _ => "Unknown".into(),
            }
        }
    };
}

mesh_message_type_to_string! {
    AgentTrustee => AgentTrusteeMessageType,
    EntityTrustee => EntityTrusteeMessageType,
    Agent => AgentMessageType,
    Metrics => MetricsMessageType,
    HttpsClient => HttpsClientMessageType,
    CertificateAgent => CertificateAgentMessageType,
    HttpsListener => HttpsListenerMessageType,
    WebsocketListener => WebsocketListenerMessageType,
    Maintenance => MaintenanceMessageType,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentIdWithAttributes {
    pub agent_id: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_type: Option<MeshEntityType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes_self: Option<Vec<MeshLinkAttributesTypeAndOp>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes_origin: Option<Vec<MeshLinkAttributesTypeAndOp>>,
}

impl AgentIdWithAttributes {
    pub fn new(
        agent_id: MeshId,
        attributes_self: Option<Vec<MeshLinkAttributesTypeAndOp>>,
        attributes_origin: Option<Vec<MeshLinkAttributesTypeAndOp>>,
    ) -> Self {
        Self {
            agent_id,
            entity_type: None,
            attributes_self,
            attributes_origin,
        }
    }
    pub fn new_no_attributes(agent_id: MeshId) -> Self {
        Self {
            agent_id,
            entity_type: None,
            attributes_origin: None,
            attributes_self: None,
        }
    }
    pub fn new_with_entity_type(
        agent_id: MeshId,
        attributes_self: Option<Vec<MeshLinkAttributesTypeAndOp>>,
        attributes_origin: Option<Vec<MeshLinkAttributesTypeAndOp>>,
        entity_type: MeshEntityType,
    ) -> Self {
        Self {
            agent_id,
            entity_type: Some(entity_type),
            attributes_self,
            attributes_origin,
        }
    }
    pub fn new_with_entity_type_no_attributes(
        agent_id: MeshId,
        entity_type: MeshEntityType,
    ) -> Self {
        Self {
            agent_id,
            entity_type: Some(entity_type),
            attributes_origin: None,
            attributes_self: None,
        }
    }
}

pub trait HasListFunctions {
    fn get_offset(&self) -> Option<u64>;
    fn get_limit(&self) -> Option<u64>;
    fn get_session_link_codes(&self) -> bool;
    fn get_include_deleted(&self) -> Option<bool>;
}

pub trait HasSetLinkCode {
    fn set_link_code(&mut self, link_code: MeshLinkCode);
}

pub fn extract_delay_from_rate_limit_error(s: &str) -> Option<i64> {
    let re = Regex::new(r"delay=(\d+)").unwrap();
    re.captures(s)
        .and_then(|cap| cap.get(1))
        .and_then(|num| num.as_str().parse::<i64>().ok())
}

/// A common type to help unify all the systems exchanging messages between enclaves.
pub type ReplyCallback<T> =
    Box<dyn FnOnce(Result<T, MeshError>) -> Result<Vec<MeshMessage>, MeshError> + Send + Sync>;

#[cfg(all(test, not(feature = "enclave")))]
mod tests {
    use alloc::borrow::Cow;

    use common_crypto::mesh_hmac_sign;
    use common_crypto::HmcHashType;

    use super::*;

    // Ensure that we can use MeshMessage::extract to unpack messages that have values that
    // "borrow" from (i.e., point into) the CBOR buffer.
    #[test]
    fn test_extract_borrow() {
        #[derive(Serialize, Deserialize)]
        struct Borrows<'a> {
            #[serde(borrow)]
            s: Cow<'a, str>,
            #[serde(borrow, with = "serde_bytes")]
            b: Cow<'a, [u8]>,
        }

        let to_encode = Borrows {
            s: Cow::Owned("I'm a string".into()),
            b: Cow::Owned(b"I'm some bytes".to_vec()),
        };

        let payload = to_vec_packed(&to_encode).unwrap();

        let message = MeshMessage::build_app_enclave_message(
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshSubsystem::Unknown,
            0,
            Some(payload),
            false,
            None,
        );

        let payload = message.payload.as_ref().unwrap();
        let payload_range = std::ops::Range {
            start: payload.as_ptr(),
            end: payload.as_ptr().wrapping_add(payload.len()),
        };

        let Borrows {
            s: Cow::Borrowed(s),
            b: Cow::Borrowed(b),
        } = message.extract().unwrap()
        else {
            panic!("deserialized result did not borrow from message");
        };

        assert!(payload_range.contains(&s.as_ptr()));
        assert!(payload_range.contains(&b.as_ptr()));
    }

    #[test]
    fn test_build_signature() {
        let mut msg = MeshMessage::build_interenclave_message(
            MeshId::from_static("foo"),
            MeshId::from_static("bar"),
            MeshId::from_static("baz"),
            MeshId::from_static("qux"),
            MeshSubsystem::Unknown,
            54321,
            MeshId::from_static("session"),
            Some(vec![77; 300 << 10]),
            MeshId::from_static("quux"),
            None,
        );
        let key = MeshId::from_static("key");

        let signature = msg.build_signature(&key.id).unwrap();

        msg.header.context_id = None;
        msg.header.metrics = None;
        msg.local_internal = None;

        let cbor = to_vec_packed(&msg).unwrap();
        let hmac = mesh_hmac_sign(
            HmcDataType::Raw,
            &key.id,
            HmcDataType::Raw,
            &cbor,
            HmcHashType::Sha256,
            HmcDataType::Raw,
        )
        .unwrap();
        assert_eq!(&signature, &hmac);
    }

    #[test]
    fn test_build_local_internal_signature() {
        let mut msg = MeshMessage::build_interenclave_message(
            MeshId::from_static("foo"),
            MeshId::from_static("bar"),
            MeshId::from_static("baz"),
            MeshId::from_static("qux"),
            MeshSubsystem::Unknown,
            54321,
            MeshId::from_static("session"),
            Some(vec![77; 300 << 10]),
            MeshId::from_static("quux"),
            None,
        );
        let key = MeshId::from_static("key");

        let signature = msg.build_local_internal_signature(&key.id).unwrap();

        msg.header.context_id = None;
        msg.header.metrics = None;

        let cbor = to_vec_packed(&msg).unwrap();
        let hmac = mesh_hmac_sign(
            HmcDataType::Raw,
            &key.id,
            HmcDataType::Raw,
            &cbor,
            HmcHashType::Sha256,
            HmcDataType::Raw,
        )
        .unwrap();
        assert_eq!(&signature, &hmac);
    }

    /*
    #[bench]
    fn foo(b: &mut test::Bencher) {
        let mut msg = MeshMessage::build_interenclave_message(
            MeshId::from_static("foo"),
            MeshId::from_static("bar"),
            MeshId::from_static("baz"),
            MeshId::from_static("qux"),
            MeshSubsystem::Unknown,
            54321,
            MeshId::from_static("session"),
            Some(vec![77; 300 << 10]),
            MeshId::from_static("quux"),
            None,
        );
        let key = MeshId::from_static("key");

        b.iter(|| {
            let _ = std::hint::black_box(msg.build_local_internal_signature(&key.id).unwrap());
        })
    }
    */
}
