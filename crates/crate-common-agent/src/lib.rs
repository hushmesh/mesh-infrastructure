//! This crate provides functions for agents to connect to their trustee and use the mesh network.

#![cfg_attr(feature = "enclave", no_std)]

#[macro_use]
extern crate alloc;

/// agent functions to send requests to their trustees or other agents
pub mod agent;

/// agent bootstrap functions
pub mod agent_bootstrap;

/// agent handlers to receive messages
pub mod agent_to_agent;

/// agent function to enforce authorization on messages received
pub mod authorization;

/// agent function to enforce authorization on messages received
pub mod authorization_handlers;

/// agent function to get links they have for an entity
pub mod lemid_links;
