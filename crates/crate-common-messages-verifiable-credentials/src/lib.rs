//! Message definitions for verifiable credential agents

#![cfg_attr(feature = "enclave", no_std)]

extern crate alloc;

/// Messages for holder agent
pub mod holder_agent_messages;

/// Messages for HSM agent
pub mod hsm_agent_messages;

/// Messages for VDR agent
pub mod vdr_agent_messages;
