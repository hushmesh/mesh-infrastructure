use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use hashbrown::HashMap;
use serde::Deserialize;
use serde::Serialize;

use common_crypto::HmcCertType;
use common_messages::message_types::HttpsListenerMessageType;
use common_messages::MeshMessage;
use common_messages::MeshSubsystem;
use common_types::cbor::to_vec_packed;
use common_types::ContextId;
use common_types::MeshError;
use common_types::MeshId;
use common_types::MeshMessageId;
use common_types::MeshSessionId;
use common_types::MeshStatusType;

#[derive(Debug, Serialize, Deserialize)]
pub struct SetCertificateRequest<'a> {
    #[serde(borrow)]
    pub private_key_pem: Cow<'a, str>,
    #[serde(borrow)]
    pub certificate_chain_pem: Cow<'a, str>,
    pub certificate_type: HmcCertType,
}

impl SetCertificateRequest<'static> {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        private_key_pem: &str,
        certificate_chain_pem: &str,
        certificate_type: HmcCertType,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = SetCertificateRequest {
            private_key_pem: private_key_pem.into(),
            certificate_chain_pem: certificate_chain_pem.into(),
            certificate_type,
        };
        let payload = to_vec_packed(&request).unwrap();
        let message = MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::HttpsListener,
            HttpsListenerMessageType::SetCertificateRequestType.into(),
            message_id,
            Some(payload),
            MeshId::empty(),
            context_id,
        );
        Ok(message)
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct HttpRequest {
    pub path: Option<String>,
    pub host: Option<String>,
    pub method: Option<String>,
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_params: Option<BTreeMap<String, String>>,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub body: Option<Vec<u8>>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub body_complete: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continue_id: Option<MeshId>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpMoreDataFromClientRequest {
    #[serde(default, with = "serde_bytes")]
    pub body: Vec<u8>,
    pub body_complete: bool,
    pub continue_id: MeshId,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpResponse {
    pub protocol: String,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<BTreeMap<String, String>>,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub body: Option<Vec<u8>>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub body_complete: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continue_id: Option<MeshId>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpMoreDataFromServerResponse {
    #[serde(default, with = "serde_bytes")]
    pub body: Vec<u8>,
    pub body_complete: bool,
    pub continue_id: MeshId,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpMoreDataFromClientResponse {
    pub continue_id: MeshId,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpMoreDataFromServerRequest {
    pub continue_id: MeshId,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpErrorInContinuationResponse {
    pub continue_id: MeshId,
}

pub fn add_cors_headers(origin: Option<String>, headers: &mut HashMap<String, String>) {
    let origin = origin.unwrap_or("*".into());
    headers.insert("Access-Control-Allow-Origin".into(), origin);
    headers.insert(
        "Access-Control-Allow-Methods".into(),
        "GET, POST, OPTIONS, DELETE, PUT".into(),
    );
    headers.insert(
        "Access-Control-Allow-Headers".into(),
        "Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With".into(),
    );
}

pub fn build_empty_http_response(message: &MeshMessage) -> Result<MeshMessage, MeshError> {
    let reply = HttpResponse {
        content_type: Some("application/json".into()),
        ..Default::default()
    };

    let payload = to_vec_packed(&reply)?;
    return Ok(message.build_reply(
        HttpsListenerMessageType::HttpResponseType.into(),
        MeshStatusType::Success,
        None,
        Some(payload),
    ));
}

impl Default for HttpResponse {
    fn default() -> Self {
        Self {
            protocol: "HTTP/1.1".into(),
            headers: None,
            body: None,
            content_type: None,
            content_length: None,
            body_complete: None,
            continue_id: None,
            status: 200,
        }
    }
}

impl HttpRequest {
    pub fn build_message(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        transport_session_id: MeshSessionId,
        path: Option<String>,
        host: Option<String>,
        method: Option<String>,
        protocol: Option<String>,
        headers: Option<impl IntoIterator<Item = (String, String)>>,
        params: Option<impl IntoIterator<Item = (String, String)>>,
        body: Option<Vec<u8>>,
        content_type: Option<String>,
        content_length: Option<u64>,
        body_complete: Option<bool>,
        continue_id: Option<MeshSessionId>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = HttpRequest {
            path,
            host,
            method,
            protocol,
            headers: headers.map(BTreeMap::from_iter),
            params: params.map(BTreeMap::from_iter),
            path_params: None,
            body,
            content_type,
            content_length,
            body_complete,
            continue_id,
        };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::HttpsListener,
            HttpsListenerMessageType::HttpRequestType.into(),
            message_id,
            Some(payload),
            transport_session_id,
            context_id,
        ))
    }

    pub fn get_param_str(&self, name: &str) -> Option<&str> {
        self.params.as_ref()?.get(name).map(String::as_str)
    }

    pub fn get_param_string(&self, name: &str) -> Option<String> {
        self.get_param_str(name).map(Into::into)
    }

    pub fn get_param_string_required(&self, name: &str) -> Result<String, MeshError> {
        self.get_param_string(name)
            .ok_or_else(|| MeshError::BadArgument(format!("missing {name:?}")))
    }

    pub fn get_param_u64(&self, name: &str) -> Result<Option<u64>, MeshError> {
        self.get_param_str(name)
            .map(|v| {
                v.parse()
                    .map_err(|_e| MeshError::BadArgument("invalid numeric value".into()))
            })
            .transpose()
    }

    pub fn get_path_param_str(&self, name: &str) -> Option<&str> {
        self.path_params.as_ref()?.get(name).map(String::as_str)
    }

    pub fn get_path_param_string(&self, name: &str) -> Option<String> {
        self.get_path_param_str(name).map(Into::into)
    }

    pub fn get_path_param_string_required(&self, name: &str) -> Result<String, MeshError> {
        self.get_path_param_string(name)
            .ok_or_else(|| MeshError::BadArgument(format!("missing {name:?}")))
    }

    pub fn get_path_param_u64(&self, name: &str) -> Result<Option<u64>, MeshError> {
        self.get_path_param_str(name)
            .map(|v| {
                v.parse()
                    .map_err(|_e| MeshError::BadArgument(format!("invalid format for {name:?}")))
            })
            .transpose()
    }

    pub fn get_bearer_token(&self) -> Option<&str> {
        let auth = self.get_header_str("authorization")?;
        ["Bearer ", "bearer "]
            .iter()
            .find_map(|b| auth.strip_prefix(b))
            .map(str::trim)
    }

    pub fn get_header_string(&self, name: &str) -> Option<String> {
        self.get_header_str(name).map(Into::into)
    }

    pub fn get_header_str(&self, name: &str) -> Option<&str> {
        self.headers.as_ref()?.get(name).map(String::as_str)
    }

    pub fn get_header_u64(&self, name: &str) -> Result<Option<u64>, MeshError> {
        self.get_header_str(name)
            .map(|v| {
                v.parse()
                    .map_err(|_e| MeshError::BadArgument("invalid numeric value".into()))
            })
            .transpose()
    }
}

impl HttpMoreDataFromClientRequest {
    pub fn build_message(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        transport_session_id: MeshSessionId,
        body: Vec<u8>,
        body_complete: bool,
        continue_id: MeshSessionId,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = HttpMoreDataFromClientRequest {
            body,
            body_complete,
            continue_id: continue_id.into(),
        };
        let payload = to_vec_packed(&request)?;
        let message = MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::HttpsListener,
            HttpsListenerMessageType::HttpMoreDataFromClientRequestType.into(),
            message_id,
            Some(payload),
            transport_session_id,
            context_id,
        );
        return Ok(message);
    }
}

impl HttpMoreDataFromServerResponse {
    pub fn build_message(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        transport_session_id: MeshSessionId,
        body: Vec<u8>,
        body_complete: bool,
        continue_id: MeshSessionId,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = HttpMoreDataFromServerResponse {
            body,
            body_complete,
            continue_id: continue_id.into(),
        };
        let payload = to_vec_packed(&request)?;
        let message = MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::HttpsListener,
            HttpsListenerMessageType::HttpMoreDataFromServerResponseType.into(),
            message_id,
            Some(payload),
            transport_session_id,
            context_id,
        );
        return Ok(message);
    }
}

impl HttpMoreDataFromClientResponse {
    pub fn build_message(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        transport_session_id: MeshSessionId,
        continue_id: MeshSessionId,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = HttpMoreDataFromClientResponse {
            continue_id: continue_id.into(),
        };
        let payload = to_vec_packed(&request)?;
        let message = MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::HttpsListener,
            HttpsListenerMessageType::HttpMoreDataFromClientResponseType.into(),
            message_id,
            Some(payload),
            transport_session_id,
            context_id,
        );
        return Ok(message);
    }
}

impl HttpMoreDataFromServerRequest {
    pub fn build_message(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        transport_session_id: MeshSessionId,
        continue_id: MeshSessionId,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = HttpMoreDataFromServerRequest {
            continue_id: continue_id.into(),
        };
        let payload = to_vec_packed(&request)?;
        let message = MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::HttpsListener,
            HttpsListenerMessageType::HttpMoreDataFromServerRequestType.into(),
            message_id,
            Some(payload),
            transport_session_id,
            context_id,
        );
        return Ok(message);
    }
}
