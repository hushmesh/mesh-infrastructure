//! Message definitions

#![cfg_attr(feature = "enclave", no_std)]

#[macro_use]
extern crate alloc;

/// Messages for making https requests
pub mod https_client_messages;

/// Messages for receiving https requests
pub mod https_listener_messages;

/// Messages for receiving websocket requests
pub mod websocket_listener_messages;
