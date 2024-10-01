use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use serde::Deserialize;
use serde::Serialize;

use common_messages::message_types::HttpsClientMessageType;
use common_messages::MeshMessage;
use common_messages::MeshSubsystem;
use common_types::ContextId;
use common_types::MeshError;
use common_types::MeshId;
use common_types::MeshMessageId;

#[derive(Debug, Serialize, Deserialize)]
pub struct CallEndpointRequest {
    pub url: String,
    pub method: String,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub body: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_parameters: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_response_size: Option<usize>,
    #[serde(default, skip_serializing_if = "<&bool as core::ops::Not>::not")]
    pub skip_verify_peer: bool,
    #[serde(default, skip_serializing_if = "<&bool as core::ops::Not>::not")]
    pub follow_redirects: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_password: Option<String>,
}

impl CallEndpointRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        url: String,
        method: String,
        body: Option<Vec<u8>>,
        query_parameters: Option<impl IntoIterator<Item = (String, String)>>,
        headers: Option<impl IntoIterator<Item = (String, String)>>,
        max_response_size: Option<usize>,
        skip_verify_peer: bool,
        follow_redirects: bool,
        proxy_url: Option<String>,
        proxy_user: Option<String>,
        proxy_password: Option<String>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = CallEndpointRequest {
            url,
            method,
            body,
            query_parameters: query_parameters.map(BTreeMap::from_iter),
            headers: headers.map(BTreeMap::from_iter),
            max_response_size,
            skip_verify_peer,
            follow_redirects,
            proxy_url,
            proxy_user,
            proxy_password,
        };
        let payload = common_types::cbor::to_vec_packed(&request)?;
        let message = MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::HttpsClient,
            HttpsClientMessageType::CallEndpointRequestType.into(),
            message_id,
            Some(payload),
            MeshId::empty(),
            context_id,
        );
        return Ok(message);
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CallEndpointResponse {
    pub http_status: u16,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub body: Option<Vec<u8>>,
    pub headers: BTreeMap<String, String>,
    pub more_data: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirected_url: Option<String>,
}
