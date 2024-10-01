//! Functions for managing asynchronous tasks and message passing that can be used when running no_std inside an enclave.

#![forbid(unused_must_use)]
#![cfg_attr(feature = "enclave", no_std)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::task::Wake;
use alloc::vec::Vec;
use core::future::Future;
use core::future::IntoFuture;
use core::mem;
use core::num::NonZeroU64;
use core::ops::DerefMut;
use core::pin::Pin;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use core::task::Context;
use core::task::Poll;
use core::task::Waker;

use hashbrown::hash_map::Entry;
use hashbrown::HashMap;
use hashbrown::HashSet;
use log::error;
use log::trace;
use log::warn;

use common_messages::message_type_string;
use common_messages::MeshMessage;
use common_messages::MeshMessageRef;
use common_messages::ReplyCallback;
use common_sync::Mutex;
use common_types::time::get_current_time_ms;
use common_types::MeshError;
use common_types::MeshMessageId;

pub use crate::expect_ready::expect_ready;
pub use crate::expect_ready::FutureNotReady;

mod expect_ready;
pub mod once_value;
pub mod oneshot;

cfg_if::cfg_if! {
    if #[cfg(any(feature = "enclave", test))] {
        fn state() -> impl DerefMut<Target = AsyncState> + 'static {
            lazy_static::lazy_static! {
                static ref EXECUTOR: Mutex<AsyncState> = Default::default();
            }
            EXECUTOR.lock().unwrap()
         }
    } else {
        use core::cell::RefCell;

        use common_sync::RwLock;
        use common_types::MeshId;

        /* When running a mesh process in simulator mode, we don't get the same levels of
         * encapsulation that we do when running things within their own enclaves. Specifically, we
         * can't have just one global AsyncState as it will end up shared between all simulated
         * enclaves.  But, all we need is for `state()` to return an `AsyncState` that belongs to
         * the implied enclave that is executing things.
         */

        lazy_static::lazy_static! {
            static ref ENCLAVE_EXECUTORS: RwLock<HashMap<MeshId, &'static Mutex<AsyncState>>> = Default::default();
        }
        thread_local! {
            static SIMULATOR_ENCLAVE: RefCell<Option<&'static Mutex<AsyncState>>> = const { RefCell::new(None) };
        }

        /// This function exists solely for app-enclave-handler, in simulator mode, to wrap any
        /// EnclaveFunction calls. This simulates each enclave having its own dedicated async
        /// executor.
        pub fn with_simulator_enclave<T>(id: MeshId, f: impl FnOnce() -> T) -> T {
            struct ClearOnDrop<'a, T>(&'a RefCell<Option<T>>);
            impl<T> Drop for ClearOnDrop<'_, T> {
                fn drop(&mut self) {
                    *self.0.borrow_mut() = None;
                }
            }
            SIMULATOR_ENCLAVE.with(|rfc| {
                let fast = ENCLAVE_EXECUTORS.read().unwrap().get(&id).copied();
                let enclave_state = fast.unwrap_or_else(|| {
                    // slow path for start-up
                    *(ENCLAVE_EXECUTORS.write().unwrap().entry(id))
                        .or_insert_with(|| Box::leak(Box::new(Default::default())))
                });

                if rfc.borrow_mut().replace(enclave_state).is_some() {
                    panic!("with_simulator_enclave called twice on the same thread");
                }
                let _dropper = ClearOnDrop(rfc); // drop on panic, too
                f()
            })
        }

        fn state() -> impl DerefMut<Target = AsyncState> + 'static {
            let enclave_state = SIMULATOR_ENCLAVE
                .with(|rfc| *rfc.borrow())
                .expect("Async activity was run without SIMULATOR_ENCLAVE_ID set");
            enclave_state.lock().unwrap()
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
struct TtlKey {
    expiry: i64,
    unique_id: NonZeroU64,
}

#[derive(Default)]
struct AsyncState {
    async_messages: HashMap<MeshMessageId, MessageEntry>,
    message_timeouts: BTreeMap<TtlKey, MeshMessageId>,
    sleeps: BTreeMap<TtlKey, Waker>,
    tasks: HashMap<NonZeroU64, Arc<Mutex<Task>>>,
    global: RunContext,
}

#[derive(Default)]
struct RunContext {
    outbound: Vec<MeshMessage>,
    ready_to_poll: HashSet<NonZeroU64>,
}

impl Drop for RunContext {
    fn drop(&mut self) {
        if self.outbound.is_empty() && self.ready_to_poll.is_empty() {
            return;
        }

        let outbound = mem::take(&mut self.outbound);
        let ready_to_poll = mem::take(&mut self.ready_to_poll);
        warn!(
            "RunContext rescuing {} messages and {} tasks",
            outbound.len(),
            ready_to_poll.len()
        );

        let global = &mut state().global;
        global.outbound = merge_messages(mem::take(&mut global.outbound), outbound);

        if global.ready_to_poll.is_empty() {
            global.ready_to_poll = ready_to_poll;
        } else {
            global.ready_to_poll.extend(ready_to_poll);
        }
    }
}

/// This function exists for process* ecalls to determine when the next pending async activity is
/// due to run.
pub fn next_expiry() -> Option<i64> {
    state().next_expiry()
}

/// If a response to a message sent with `send_message()` has arrived in an enclave's `process()`,
/// it shall be consumed via the callback returned here. The next call to `run_all_pending` will
/// poll the `Future` that sent the message, which will proceed.
///
/// Any callback returned **MUST** be immediately used with the message whose ID was queried.
pub fn get_callback_for_message(id: &MeshMessageId) -> Option<impl FnOnce(MeshMessageRef)> {
    let mut state = state();
    let entry = state.async_messages.get_mut(id)?;
    if !matches!(entry.state, AsyncRequestResponse::Waiting(_)) {
        // This could happen if a response is received just after it timed out.
        error!(
            "get_callback_for_message was called for a message in state '{:?}'",
            entry.state
        );
        return None;
    }

    // To allow the closure to use `entry` without looking it up again, we need a tiny bit of
    // unsafe.  At this very point, we know that `entry` is a valid `&mut`, and it's borrowing from
    // `state`.  We must move state into the closure, though.  The lock will still be held, and
    // everything behind it will remain untouched....
    let entry: *mut _ = entry;
    Some(move |msg: MeshMessageRef| {
        // Safety: `entry` logically borrows from `state` before it is moved, but moving alone
        // doesn't invalidate the pointer.
        let (waker, ttl_key) = (unsafe { &mut *entry }).accept_response(Ok(msg.into_static()));
        state.message_timeouts.remove(&ttl_key);
        drop(state); // state cannot be held by a thread waking a task...
        waker
            .expect("response received for message not in Waiting state")
            .wake();
    })
}

struct MessageEntry {
    state: AsyncRequestResponse,
    ttl_key: Option<TtlKey>,
}

impl AsyncState {
    fn take_rescued(
        &mut self,
    ) -> (
        Vec<(Option<NonZeroU64>, Arc<Mutex<Task>>)>,
        Vec<MeshMessage>,
    ) {
        let ready_to_poll = &mut self.global.ready_to_poll;

        if ready_to_poll.capacity() / 2 > ready_to_poll.len() {
            ready_to_poll.shrink_to_fit();
        }
        // collect() won't make use of the size_hint() provided by filter_map.  But, the
        // probability than an awoken task id be missing from `tasks` is incredibly low, so it
        // makes sense to pre-allocate the full sized Vec.
        let mut tasks = Vec::with_capacity(ready_to_poll.len());
        tasks.extend(
            ready_to_poll
                .drain()
                .filter_map(|id| self.tasks.get(&id).map(|v| (Some(id), v.clone()))),
        );

        (tasks, mem::take(&mut self.global.outbound))
    }

    fn insert_message(&mut self, message: MeshMessage, expiry: i64) {
        let unique_id = next_id();
        let ttl_key = TtlKey { expiry, unique_id };
        let message_id = message.header.message_id;
        let entry = MessageEntry {
            state: AsyncRequestResponse::Pending(message),
            ttl_key: Some(ttl_key),
        };

        self.async_messages.insert(message_id, entry);
        self.message_timeouts.insert(ttl_key, message_id);
    }

    fn remove_message(&mut self, message_id: &MeshMessageId) {
        if let Some(entry) = self.async_messages.remove(message_id) {
            if let Some(ttl_key) = &entry.ttl_key {
                self.message_timeouts.remove(ttl_key);
            }
            if matches!(entry.state, AsyncRequestResponse::Waiting(_)) {
                // Generally, messages shouldn't wait long in outbound, so even if this isn't the
                // most efficient way possible to prune messages, it shouldn't make much of a
                // difference overall.
                self.global
                    .outbound
                    .retain(|msg| &msg.header.message_id != message_id);
                LOCAL_CONTEXT::with(|local| {
                    if let Some(ctx) = local {
                        ctx.outbound
                            .retain(|msg| &msg.header.message_id != message_id);
                    }
                })
            }
        }
    }

    fn next_expiry(&self) -> Option<i64> {
        // If there is work pending in the global state, we can request to be called again
        // immediately.
        if !self.global.ready_to_poll.is_empty() {
            return Some(0);
        }
        [
            self.message_timeouts
                .first_key_value()
                .map(|(key, _)| key.expiry),
            self.sleeps.first_key_value().map(|(key, _)| key.expiry),
        ]
        .into_iter()
        .flatten()
        .min()
    }
}

// A task shall never have an id of zero.
fn next_id() -> NonZeroU64 {
    static IDS: AtomicU64 = AtomicU64::new(1);
    let id = IDS.fetch_add(1, Ordering::Relaxed);
    // Safety: IDS will not overflow for hundreds if not thousands of years.
    unsafe { NonZeroU64::new_unchecked(id) }
}

/// Spawn a task in the background. It's the responsibility of the task to make sure it
/// completes itself, emitting messages via `send_message` and/or `relay_messages`. Generally,
/// any errors encountered during the execution of the task would be handled by the task. If an
/// error escapes to the end, it will be logged, but otherwise ignored.
#[inline]
pub fn spawn_task<F, IF>(fut: IF)
where
    IF: IntoFuture<IntoFuture = F>,
    F: Future<Output = Result<(), MeshError>> + Sync + Send + 'static,
{
    let task = future_to_task(fut);
    insert_task(task, true)
}

#[inline]
/// Helper for spawn_task*. Inlined to help encourage tasks be created directly on the heap.
fn future_to_task<F, IF>(
    fut: IF,
) -> Pin<Box<dyn Future<Output = Result<(), MeshError>> + Send + Sync + 'static>>
where
    IF: IntoFuture<IntoFuture = F>,
    F: Future<Output = Result<(), MeshError>> + Sync + Send + 'static,
{
    // We hold our tasks in Pin<Box<dyn Future<...>>>. `async{}` blocks are opaque Futures, and are
    // thus automatically idempotent IntoFutures, and these are precisely what we want to lift into
    // a Pin<Box<...>>>. But, if we've implemented IntoFuture for some type that runs a bunch of
    // `async fn` methods, it needs to return a concrete Future type, the best option is
    // Pin<Box<dyn Future<...>>>. If we did the naive thing, we'd be left with essentially
    // Pin<Box<Pin<Box<...>>>>, requiring each call to poll() to jump through the extra pointer.
    // Instead, we can flatten it here! This will also catch `Box::pin(async {})`.
    let boxed_any: Box<dyn core::any::Any> = Box::new(fut.into_future());
    match boxed_any
        .downcast::<Pin<Box<dyn Future<Output = Result<(), MeshError>> + Send + Sync + 'static>>>()
    {
        Ok(pinned) => {
            trace!("downcasted Future directly into Pin<Box<dyn Future...>>!");
            *pinned
        }
        Err(boxed_any) => {
            trace!("Future was not Pin<Box<dyn ...>>, so pinning...");
            match boxed_any.downcast::<F>() {
                Ok(opaque_fut) => Box::into_pin(opaque_fut),
                Err(_) => unreachable!("fut.into_future() somehow did not return F"),
            }
        }
    }
}

/// Spawn a task which will NOT be executed within any current thread context, but by the next call
/// to run_expired.
#[inline]
pub fn spawn_task_external<F, IF>(fut: IF)
where
    IF: IntoFuture<IntoFuture = F>,
    F: Future<Output = Result<(), MeshError>> + Sync + Send + 'static,
{
    let task = future_to_task(fut);
    insert_task(task, false);
}

/// When called from outside of run_local/run_with_context, this will create a context and start
/// the Future within it, returning any messages created.  If run from within an existing context,
/// the Future will be spawned but its execution will be deferred until the context finishes, and
/// an empty Vec will be returned.
///
/// The intended use of this is within an ecall like get_init_messages, where a Future may need to
/// be started to bootstrap an actor.  Such a Future will likely first block awaiting a response to
/// a message, and that outgoing message will be returned.
pub fn start_one_task<F, IF>(fut: IF) -> Vec<MeshMessage>
where
    IF: IntoFuture<IntoFuture = F>,
    F: Future<Output = Result<(), MeshError>> + Sync + Send + 'static,
{
    if LOCAL_CONTEXT::is_set() {
        spawn_task(fut);
        Vec::new()
    } else {
        run_with_context(move || {
            spawn_task(fut);
            finish_local_context()
        })
    }
}

/// This is just a helper for [`spawn_task`]/[`spawn_task_external`]. Those public functions are
/// made inlined to help encourage that any Future is created on the heap and not the stack first,
/// but this part does not need to be.
fn insert_task(
    fut: Pin<Box<dyn Future<Output = Result<(), MeshError>> + Send + Sync + 'static>>,
    try_local_context: bool,
) {
    let task_id = next_id();
    let waker: Waker = Arc::new(MeshWaker { task_id }).into();
    let task = Arc::new(Mutex::new(Task {
        fut: Some(fut),
        waker,
    }));
    let mut state = state();
    state.tasks.insert(task_id, task);
    if try_local_context {
        LOCAL_CONTEXT::with(|local| {
            local
                .map(|ctx| &mut ctx.ready_to_poll)
                .unwrap_or(&mut state.global.ready_to_poll)
                .insert(task_id);
        })
    } else {
        state.global.ready_to_poll.insert(task_id);
    }
}

/// run_expired is meant to be called from a process_timer ecall, It is intended to be called
/// exclusively by common_enclave_processor::process_timer_results.
///
/// Any time-based Futures due to fire will be run. Additionally, any tasks awoken by recent failed
/// calls to run_local.
///
/// # Panics
///
/// This function will panic if called outside of [`run_with_context`].
pub fn run_expired() -> (Vec<MeshMessage>, Option<i64>) {
    assert!(LOCAL_CONTEXT::is_set());

    let wakers = {
        let mut state = state();
        let now = get_current_time_ms();
        let not_expired = state.message_timeouts.split_off(&TtlKey {
            expiry: now + 1,
            unique_id: NonZeroU64::MIN,
        });
        let expired = mem::replace(&mut state.message_timeouts, not_expired);

        let mut wakers = expired
            .into_values()
            .map(|id| {
                let (maybe_waker, ttl_key) = state
                    .async_messages
                    .get_mut(&id)
                    .expect("expired message had no entry in async_messages")
                    .accept_response(Err(MeshError::TimeoutError));
                state.message_timeouts.remove(&ttl_key);
                maybe_waker
            })
            .collect::<Vec<_>>();

        {
            let not_expired = state.sleeps.split_off(&TtlKey {
                expiry: now + 1,
                // Safety: 1 is not 0.
                unique_id: unsafe { NonZeroU64::new_unchecked(1) },
            });
            let expired = mem::replace(&mut state.sleeps, not_expired);

            wakers.extend(expired.into_values().map(Some));
        }

        wakers
    };
    for waker in wakers.into_iter().flatten() {
        waker.wake();
    }

    let (mut tasks, rescued_messages) = state().take_rescued();
    for (task_id, task) in tasks.iter_mut() {
        if task.lock().unwrap().do_poll() {
            *task_id = None; // task is NOT done, do not remove it.
        }
    }

    if tasks.iter().any(|(task_id, _)| task_id.is_some()) {
        // If any of the tasks contain any values which do anything async related in their Drops,
        // we'd risk deadlocks by dropping tasks while the lock is held.
        let defer_drop = {
            let mut state = state();
            tasks
                .into_iter()
                .filter_map(|(task_id, _)| task_id)
                .filter_map(|task_id| state.tasks.remove(&task_id))
                .collect::<Vec<_>>()
        };
        drop(defer_drop);
    }

    let local_messages = finish_local_context();
    let messages = merge_messages(rescued_messages, local_messages);

    (messages, next_expiry())
}

// A convenience function to logically concatenate two Vecs when frequently at least one of them is
// empty.  If one is empty, the other will be returned without making a copy.
fn merge_messages(a: Vec<MeshMessage>, b: Vec<MeshMessage>) -> Vec<MeshMessage> {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => Vec::new(),
        (true, false) => b,
        (false, true) => a,
        (false, false) => a.into_iter().chain(b).collect(),
    }
}

/// run_local is meant to the be direct line to the async runtime that an ecall to process will
/// invoke. The closure passed to it is expected to trigger some action based on an incoming
/// message.
///
/// Any async activity implied by this action (and ONLY async activity directly triggered by this
/// message) will happen entirely within this thread, and all created outgoing messages will be
/// returned, unless the closure returns an error.
///
/// If there is an error, any pending awoken tasks and outgoing messages will be picked up in the
/// next call to run_expired, which should be invoked by process_timer.
pub fn run_local(
    f: impl FnOnce() -> Result<Vec<MeshMessage>, MeshError>,
) -> Result<Vec<MeshMessage>, MeshError> {
    run_with_context(move || {
        let external_messages = f()?;
        let internal_messages = finish_local_context();
        Ok(merge_messages(external_messages, internal_messages))
    })
}

/// Execute some async activity with a thread-local context that will capture all outgoing
/// messages.  The only intended outside use of this function is
/// `common_enclave_processor::process_timer_results`, which shall execute [`run_expired`] within
/// the closure.
pub fn run_with_context<R>(f: impl FnOnce() -> R) -> R {
    let _cleanup = LOCAL_CONTEXT::setup();

    let result = f();

    // f() may or may not have executed finish_local_context(). If it did not, because an error was
    // encountered, any awoken tasks or pending outgoing messages will be "rescued" when the local
    // RunContext is dropped here.
    drop(_cleanup);

    result
}

/// Polls all tasks awoken in the current LOCAL_CONTEXT, and any new tasks created or awoken in the
/// process. When done, all outbound messages from LOCAL_CONTEXT are returned.
fn finish_local_context() -> Vec<MeshMessage> {
    let mut tasks = Vec::new();
    loop {
        tasks.clear();
        let tasks = LOCAL_CONTEXT::with(|local| {
            let ready_to_poll = &mut local.unwrap().ready_to_poll;
            if !ready_to_poll.is_empty() {
                tasks.reserve(ready_to_poll.len());
                let state = state();
                tasks.extend(
                    ready_to_poll
                        .drain()
                        .filter_map(|id| state.tasks.get(&id).map(|v| (Some(id), v.clone()))),
                );
            }
            &mut tasks
        });
        if tasks.is_empty() {
            break;
        }

        for (task_id, task) in tasks.iter_mut() {
            if task.lock().unwrap().do_poll() {
                *task_id = None; // task is NOT done, do not remove it.
            }
        }

        if tasks.iter().any(|(task_id, _)| task_id.is_some()) {
            let mut state = state();
            for task_id in tasks.drain(..).filter_map(|(task_id, _)| task_id) {
                state.tasks.remove(&task_id);
            }
        }
    }
    LOCAL_CONTEXT::with(|local| mem::take(&mut local.unwrap().outbound))
}

/// Sends a message, registering the necessary callback bits within `requests`. This must only
/// be called from Futures executed by [`spawn_task`].
pub async fn send_message(
    message: MeshMessage,
    ttl_ms: Option<i64>,
) -> Result<MeshMessage, MeshError> {
    let fut = MeshMessageFuture {
        message_id: message.header.message_id,
        done: false,
    };
    let expiry = get_current_time_ms() + ttl_ms.unwrap_or(10_000);
    state().insert_message(message, expiry);
    fut.await
}

/// Creates an `.await`-able bridge to message passing events handled in the RequestTable system.
/// Any system that expects a ReplyCallback to advance some state to its next step may use this
/// instead.  You may do something roughly like,
/// ```ignore
/// let (send, reply_callback) = make_callback_forwarder();
/// let msgs: Vec<MeshMessage> = do_something(..., reply_callback);
/// send(msgs).await
/// ```
pub fn make_callback_forwarder<T, I>(
) -> (impl FnOnce(I) -> ReplyCallbackFuture<T>, ReplyCallback<T>)
where
    T: Send + 'static,
    I: IntoIterator<Item = MeshMessage>,
{
    let (fut, reply_callback) = ReplyCallbackFuture::new();
    let send = move |msgs| {
        forward_messages(msgs);
        fut
    };
    (send, reply_callback)
}

/// Sends messages without waiting on them.
pub fn forward_messages<I: IntoIterator<Item = MeshMessage>>(msgs: I) {
    // It is possible for a complicated Iterator of messages to trigger calls back into
    // common_async, making this function reetrant. Thus, we cannot use `extend` while locking
    // either LOCAL_CONTEXT or state()!
    if LOCAL_CONTEXT::is_set() {
        for msg in msgs {
            LOCAL_CONTEXT::with(move |local| local.unwrap().outbound.push(msg));
        }
    } else {
        for msg in msgs {
            state().global.outbound.push(msg);
        }
    }
}

struct Task {
    fut: Option<Pin<Box<dyn Future<Output = Result<(), MeshError>> + Sync + Send>>>,
    waker: Waker,
}

impl core::fmt::Debug for Task {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("Task")
    }
}

impl Task {
    // Poll the Task's internal Future. Returns true if it returns Pending and needs to be polled
    // again.
    fn do_poll(&mut self) -> bool {
        let Some(fut) = self.fut.as_mut() else {
            return false;
        };
        let mut cx = Context::from_waker(&self.waker);
        match Pin::new(fut).poll(&mut cx) {
            Poll::Pending => true,
            Poll::Ready(res) => {
                // Ensure no concurrent call may poll() again.
                self.fut = None;
                if let Err(err) = res {
                    error!("Task returned error: {err}");
                }
                false
            }
        }
    }
}

struct MeshWaker {
    task_id: NonZeroU64,
}

impl Wake for MeshWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref()
    }
    fn wake_by_ref(self: &Arc<Self>) {
        LOCAL_CONTEXT::with(|local| match local {
            Some(ctx) => ctx.ready_to_poll.insert(self.task_id),
            None => state().global.ready_to_poll.insert(self.task_id),
        });
    }
}

pub(crate) enum AsyncRequestResponse {
    Pending(MeshMessage),
    Waiting(Waker),
    Received(Result<MeshMessage, MeshError>),
}

impl core::fmt::Debug for AsyncRequestResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(match self {
            Self::Pending(_) => "Pending",
            Self::Waiting(_) => "Waiting",
            Self::Received(_) => "Received",
        })
    }
}

impl MessageEntry {
    /// The TtlKey returned must be removed from `message_timeouts`.
    fn accept_response(
        &mut self,
        response: Result<MeshMessage, MeshError>,
    ) -> (Option<Waker>, TtlKey) {
        let ttl_key = self
            .ttl_key
            .take()
            .expect("accept_response called on MessageEntry without a ttl_key");
        let is_err = response.is_err();
        match mem::replace(&mut self.state, AsyncRequestResponse::Received(response)) {
            AsyncRequestResponse::Waiting(waker) => (Some(waker), ttl_key),
            AsyncRequestResponse::Pending(msg) if is_err => {
                // This could happen if a machine is very overloaded, or if there is a bug.
                error!(
                    "message received error before it was sent, {:?}:{}",
                    msg.header.subsystem,
                    message_type_string(msg.header.subsystem, msg.header.message_type),
                );
                (None, ttl_key)
            }
            illegal => panic!("accept_response found AsyncRequestResponse::{illegal:?}"),
        }
    }
}

struct MeshMessageFuture {
    message_id: MeshMessageId,
    done: bool,
}

impl Drop for MeshMessageFuture {
    fn drop(&mut self) {
        state().remove_message(&self.message_id);
    }
}

impl Future for MeshMessageFuture {
    type Output = Result<MeshMessage, MeshError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        use AsyncRequestResponse as ARR;

        if self.done {
            error!("done MeshMessageFuture was polled");
            return Poll::Ready(Err(MeshError::BadState)); // ??? something wrong
        }

        let mut state = state();
        match state.async_messages.entry(self.message_id) {
            Entry::Vacant(_) => panic!("message was polled without entry in async_messages"),
            Entry::Occupied(mut oe) => match &mut oe.get_mut().state {
                entry @ ARR::Pending(_) => {
                    let waiting = ARR::Waiting(cx.waker().clone());
                    let ARR::Pending(message) = mem::replace(entry, waiting) else {
                        unreachable!()
                    };
                    LOCAL_CONTEXT::with(|local| {
                        local
                            .expect("MeshMessageFuture polled without LOCAL_CONTEXT")
                            .outbound
                            .push(message)
                    });
                    Poll::Pending
                }
                ARR::Waiting(waker) => {
                    *waker = cx.waker().clone();
                    Poll::Pending
                }
                ARR::Received(_) => {
                    let ARR::Received(result) = oe.remove().state else {
                        unreachable!()
                    };
                    drop(state);
                    self.done = true;
                    Poll::Ready(result)
                }
            },
        }
    }
}

/// `ReplyCallbackFuture` is the `Future` type used with [`make_callback_forwarder`].
pub struct ReplyCallbackFuture<T> {
    state: Arc<Mutex<ReplyCallbackState<T>>>,
    done: bool,
}

struct ReplyCallbackState<T> {
    result: Option<Result<T, MeshError>>,
    waker: Option<Waker>,
}

impl<T> Default for ReplyCallbackState<T> {
    fn default() -> Self {
        // We don't need `T` to implement `Default`, but that means `derive` won't work.
        Self {
            result: None,
            waker: None,
        }
    }
}

impl<T: Send + 'static> ReplyCallbackFuture<T> {
    fn new() -> (Self, ReplyCallback<T>) {
        let state = Arc::new(Mutex::new(ReplyCallbackState::default()));
        let state_clone = state.clone();
        let callback = Box::new(move |reply| {
            let mut state = state_clone.lock().unwrap();
            state.result = Some(reply);
            // It is theoretically possible for the callback to be executed before the future is
            // polled, in which case there's nothing to wake.
            if let Some(waker) = state.waker.take() {
                waker.wake();
            }
            Ok(Vec::new())
        });
        let future = Self { state, done: false };
        (future, callback)
    }
}

impl<T> Future for ReplyCallbackFuture<T> {
    type Output = Result<T, MeshError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        if self.done {
            error!("poll called on done ReplyCallbackFuture");
            return Poll::Ready(Err(MeshError::BadState));
        }

        let mut state = self.state.lock().unwrap();
        match state.result.take() {
            None => {
                state.waker = Some(cx.waker().clone());
                Poll::Pending
            }
            Some(res) => {
                drop(state);
                self.done = true;
                Poll::Ready(res)
            }
        }
    }
}

pub fn sleep(time_ms: i64) -> impl Future<Output = ()> {
    Sleep::new(time_ms)
}

struct Sleep(TtlKey);

impl Sleep {
    fn new(time_ms: i64) -> Self {
        let expiry = get_current_time_ms() + time_ms;
        let unique_id = next_id();
        Sleep(TtlKey { expiry, unique_id })
    }
}

impl Future for Sleep {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let now = get_current_time_ms();
        if now >= self.0.expiry {
            state().sleeps.remove(&self.0);
            Poll::Ready(())
        } else {
            state().sleeps.insert(self.0, cx.waker().clone());
            Poll::Pending
        }
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        state().sleeps.remove(&self.0);
    }
}

struct Timeout<T, F>
where
    F: Future<Output = T>,
{
    sleep: Sleep,
    fut: F,
}

/// Takes a [`Future`] and wraps it in a new future that yields [`Option<T>`]. `Some` is returned
/// if the `Future` returns before `time_ms`, otherwise `None` shall be returned after `time_ms`
/// has elapsed.
#[inline]
pub fn timeout<T, F>(fut: F, time_ms: i64) -> impl Future<Output = Option<T>>
where
    F: Future<Output = T>,
{
    let sleep = Sleep::new(time_ms);
    Timeout { sleep, fut }
}

impl<T, F> Future for Timeout<T, F>
where
    F: Future<Output = T>,
{
    type Output = Option<T>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        // Safety: `self.fut` can be Pin because `self` is.
        if let Poll::Ready(val) =
            unsafe { self.as_mut().map_unchecked_mut(|s| &mut s.fut) }.poll(cx)
        {
            return Poll::Ready(Some(val));
        }

        // Safety: `self.sleep` can be Pin because `self` is, but it's also Unpin so it doesn't
        // matter.
        match unsafe { self.map_unchecked_mut(|s| &mut s.sleep) }.poll(cx) {
            Poll::Pending => Poll::Pending,       // there's still time
            Poll::Ready(()) => Poll::Ready(None), // timer has expired
        }
    }
}

/// LOCAL_CONTEXT used to be a `thread_local!` variable. But, we no longer have access to those in
/// enclaves without `std` or the unstable `#[thread_local]` attribute. The standard workaround for
/// this problem, for years per https://github.com/rust-lang/rust/issues/29594, is a C shim.
#[allow(non_snake_case)]
mod LOCAL_CONTEXT {
    use alloc::boxed::Box;
    use core::ffi::c_void;

    use super::RunContext;

    #[link(name = "async_local_context", kind = "static")]
    extern "C" {
        fn local_context() -> *mut *mut c_void;
    }

    pub(super) fn is_set() -> bool {
        with(|local| local.is_some())
    }

    pub(super) fn with<F, T>(f: F) -> T
    where
        F: FnOnce(Option<&mut RunContext>) -> T,
    {
        // Safety: local_context shall return a non-NULL pointer to the pointer which may or may
        // not currently be a RunContext;
        let maybe_ptr = core::ptr::NonNull::new(unsafe { local_context().read().cast() });
        // Safety: The RunContext for this thread will have been initialized and shall only ever be
        // accessed by one thread.
        f(maybe_ptr.map(|mut ptr| unsafe { ptr.as_mut() }))
    }

    pub(super) fn setup() -> impl Drop {
        let ctx: *mut _ = Box::leak(Box::new(RunContext::default()));
        log::trace!("local context pointer: {:?}", unsafe { local_context() });
        // Safety: local_context() is this thread's exclusive holder for a *mut RunContext.
        if !(unsafe { local_context().replace(ctx.cast()) }).is_null() {
            panic!("LOCAL_CONTEXT was already set");
        }

        struct OnDrop;
        impl Drop for OnDrop {
            fn drop(&mut self) {
                // Safety: ptr came from Box::leak, above.
                let ctx = unsafe {
                    let ptr = local_context().replace(core::ptr::null_mut());
                    assert!(!ptr.is_null(), "LOCAL_CONTEXT was NULL!");
                    Box::from_raw(ptr)
                };
                drop(ctx);
            }
        }
        OnDrop
    }

    #[cfg(all(test, not(feature = "enclave")))]
    #[test]
    fn test_static_thread_local() {
        use core::sync::atomic::AtomicPtr;
        use core::sync::atomic::Ordering;

        // Safety: we're trusting local_context to simply return a pointer to a thread local
        // variable, static variable.
        let check_local_context = || unsafe {
            let ptr = local_context();
            // Should the variable happen not to be thread_local, we'd expect things to blow up
            // here quickly.
            const DANGLING: *mut c_void = core::ptr::null_mut::<c_void>().wrapping_add(1);
            assert!(AtomicPtr::from_ptr(ptr)
                .swap(DANGLING, Ordering::SeqCst)
                .is_null());
            // Ensure that we did actually set a value at our thread local pointer.
            core::sync::atomic::fence(Ordering::SeqCst);
            assert_eq!(local_context().read_volatile(), DANGLING);
            ptr as usize
        };

        // This testing method is destructive to thread local variables, so we'll ensure it
        // actually only runs on ephemeral threads...
        std::thread::spawn(move || {
            // We want to start 5 new threads in parallel and ensure that none of them are sharing a
            // local_state() pointer.
            const CHECK_THREADS: usize = 5;
            let pending = core::sync::atomic::AtomicUsize::new(CHECK_THREADS);
            let wait = std::sync::Condvar::new();
            let ready = std::sync::Mutex::new(false);
            std::thread::scope(|s| {
                let start = std::time::Instant::now();
                let own = check_local_context();

                let handles: [_; CHECK_THREADS] = std::array::from_fn(|_| {
                    s.spawn(|| {
                        pending.fetch_sub(1, Ordering::Relaxed); // signal that we are running.
                        let lock = ready.lock().unwrap(); // wait until all are running...
                        drop(wait.wait_while(lock, |ready| !*ready).unwrap());
                        check_local_context()
                    })
                });

                // The threads are all being initialized, we must wait until they are all running in
                // parallel...
                while pending.load(Ordering::Relaxed) > 0 {
                    assert!(
                        start.elapsed() < std::time::Duration::from_secs(60),
                        "threads haven't started after 60 seconds"
                    );
                    std::thread::yield_now();
                }
                // Now that all the threads have started, they may finish...
                *ready.lock().unwrap() = true;
                wait.notify_all();

                let others = hashbrown::HashSet::<usize>::from_iter(
                    handles.into_iter().map(|handle| handle.join().unwrap()),
                );

                assert_eq!(others.len(), CHECK_THREADS);
                assert!(!others.contains(&own));
            })
        })
        .join()
        .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttlkey() {
        // We're relying on `derive(PartialOrd,Ord)` to check the attributes in order. This test
        // simply aims to ensure that isn't accidentially changed.
        let a = TtlKey {
            expiry: 1,
            unique_id: 2.try_into().unwrap(),
        };
        let b = TtlKey {
            expiry: 2,
            unique_id: 1.try_into().unwrap(),
        };
        assert!(a < b);
    }
}
