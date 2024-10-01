//! Functions actors (agents and trustees) use to process incoming messages an timers.  This uses the common-async crate.

#![forbid(unused_must_use)]
#![no_std]

#[macro_use]
extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

use common_messages::message_type_string;
use common_messages::MeshMessage;
use common_messages::MeshMessageHeader;
use common_messages::MeshMessageRef;
use common_sessions::request_table::RequestTable;
use common_sessions::response_table::ResponseData;
use common_sessions::response_table::ResponseTable;
use common_sessions::routing_table::MeshStateMachineType;
use common_sessions::routing_table::RequestResponseRoutingTable;
use common_sessions::routing_table::RoutingTable;
use common_types::MeshError;

use log::error;
use log::log_enabled;
use log::trace;
use log::Level::Debug;

#[inline]
pub fn process<'c>(
    message: MeshMessageRef<'c>,
    routing_table: RoutingTable,
    mut requests: RequestTable,
) -> Result<(Vec<MeshMessageRef<'c>>, Option<i64>), MeshError> {
    let requests_ref = &mut requests;
    let messages = common_async::run_local(move || {
        let MeshMessageHeader {
            ref message_id,
            subsystem,
            message_type,
            ..
        } = message.header;
        if let Some(route) = routing_table.find_route(subsystem, message_type) {
            trace!("found message route {message_id:?}");
            (route.router_callback)(message.into_static())
        } else if let Some(async_callback) = common_async::get_callback_for_message(message_id) {
            trace!("async message response received for pending message id {message_id:?}");
            async_callback(message);
            // no messages will be produced until polled below...
            Ok(Vec::new())
        } else if let Some(reply) = requests_ref.find_and_remove_request(message_id) {
            trace!("found message callback {message_id:?}");
            (reply.reply_callback)(Ok(message.into_static()))
        } else {
            error!(
                "no handler for {:?} type {}{} - it may be response that came in after timeout",
                subsystem,
                message_type_string(subsystem, message_type),
                log_enabled!(Debug)
                    .then(|| format!(", id {message_id:?}"))
                    .unwrap_or_default()
            );
            Err(MeshError::NoHandler)
        }
    })?;
    let next_timeout = [common_async::next_expiry(), requests.next_expiry()]
        .into_iter()
        .flatten()
        .min();
    Ok((messages, next_timeout))
}

#[inline]
pub fn process_with_responses<'c, R, S>(
    message: MeshMessageRef<'c>,
    routing_table: RequestResponseRoutingTable<R>,
    mut requests: RequestTable,
    mut responses: ResponseTable<S>,
    response_routes: RequestResponseRoutingTable<S>,
    response_handler: impl FnOnce(
        MeshMessage,
        ResponseData<S>,
        &Box<
            dyn Fn(
                    Result<MeshMessage, MeshError>,
                    MeshStateMachineType,
                    S,
                ) -> Result<Vec<MeshMessage>, MeshError>
                + Send
                + Sync,
        >,
    ) -> Result<Vec<MeshMessage>, MeshError>,
) -> Result<(Vec<MeshMessageRef<'c>>, Option<i64>), MeshError> {
    let requests_ref = &mut requests;
    let responses_ref = &mut responses;
    let messages = common_async::run_local(move || {
        let MeshMessageHeader {
            ref message_id,
            subsystem,
            message_type,
            ..
        } = message.header;

        if let Some(route) = routing_table.find_route(subsystem, message_type) {
            trace!("found message route {message_id:?}");
            (route.router_callback)(message.into_static())
        } else if let Some(response_data) = responses_ref.find_and_remove_response(message_id) {
            trace!("found message response {message_id:?}");
            let route = response_routes
                .find_response_route(subsystem, message_type, response_data.mesh_state_machine)
                .ok_or_else(|| {
                    error!(
                        "No matching response route found for message {:?}",
                        message.header
                    );
                    MeshError::NoHandler
                })?;
            response_handler(message.into_static(), response_data, &route.router_callback)
        } else if let Some(async_callback) = common_async::get_callback_for_message(message_id) {
            trace!("async message response received for pending message id {message_id:?}");
            async_callback(message);
            // `run_local` will run any Task(s) awoken by this message and return any messages
            // produced
            Ok(Vec::new())
        } else if let Some(reply) = requests_ref.find_and_remove_request(message_id) {
            trace!("found message callback {message_id:?}");
            (reply.reply_callback)(Ok(message.into_static()))
        } else {
            error!(
                "no handler for {:?} type {}{} - it may be response that came in after timeout",
                subsystem,
                message_type_string(subsystem, message_type),
                log_enabled!(Debug)
                    .then(|| format!(", id {message_id:?}"))
                    .unwrap_or_default()
            );
            Err(MeshError::NoHandler)
        }
    })?;
    let next_timeout = [
        common_async::next_expiry(),
        requests.next_expiry(),
        responses.next_expiry(),
    ]
    .into_iter()
    .flatten()
    .min();
    Ok((messages, next_timeout))
}

#[inline]
pub fn process_timer_results<I>(pairs: impl FnOnce() -> I) -> (Vec<MeshMessage>, Option<i64>)
where
    I: IntoIterator<Item = (Vec<MeshMessage>, Option<i64>)>,
{
    common_async::run_with_context(move || {
        let (message_chunks, expiries): (Vec<Vec<_>>, Vec<_>) = pairs()
            .into_iter()
            .chain(core::iter::once(common_async::run_expired()))
            .unzip();

        let messages = message_chunks.into_iter().flatten().collect();
        let next_expiry = expiries
            .into_iter()
            .filter_map(core::convert::identity)
            .min();

        (messages, next_expiry)
    })
}
