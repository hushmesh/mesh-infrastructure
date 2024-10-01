use alloc::sync::Arc;
use alloc::sync::Weak;
use alloc::vec::Vec;
use core::future::Future;
use core::future::IntoFuture;
use core::mem;
use core::pin::Pin;
use core::task::Context;
use core::task::Poll;
use core::task::Waker;

use common_types::MeshError;

use crate::Mutex;

#[derive(Clone)]
pub struct OnceValue<T>(Inner<T>)
where
    T: Clone + Send + Sync;

#[derive(Clone)]
struct InnerFuture<T>(Inner<T>)
where
    T: Clone + Send + Sync;

type Inner<T> = Arc<Mutex<State<T>>>;

enum State<T> {
    Pending(Vec<Waker>),
    Ready(T),
}

impl<T> OnceValue<T>
where
    T: Clone + Send + Sync + 'static,
{
    /// Start a task that ultimately creates a value. Each call to [`OnceValue::get`] produces a
    /// [`Future`] that lets the caller `.await` the value. Multiple tasks may do this and each
    /// will get their own [`Clone`].
    pub fn new<F, IF>(fut: IF) -> Self
    where
        IF: IntoFuture<IntoFuture = F>,
        F: Future<Output = T> + Send + Sync + 'static,
    {
        let inner = Arc::new(Mutex::new(State::Pending(Vec::new())));
        crate::spawn_task(FillFuture {
            fut: fut.into_future(),
            state: Some(Arc::downgrade(&inner)),
        });
        Self(inner)
    }

    /// If you need to inject values created from some other source into a collection full of
    /// OnceValues, you can create an already-ready OnceValue.
    pub fn ready(v: T) -> Self {
        Self(Arc::new(Mutex::new(State::Ready(v))))
    }

    /// Returns a Future which will block until the value is ready, returning a clone.
    pub fn get(&self) -> impl Future<Output = T> + Send + Sync + 'static {
        InnerFuture(self.0.clone())
    }

    /// If the value is ready, this will return a clone. Otherwise, None if its Future is still
    /// pending.
    pub fn try_get(&self) -> Option<T> {
        match &*self.0.lock().unwrap() {
            State::Ready(v) => Some(v.clone()),
            _ => None,
        }
    }
}

impl<T> Future for InnerFuture<T>
where
    T: Clone + Send + Sync,
{
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut *self.0.lock().unwrap() {
            State::Ready(v) => Poll::Ready(v.clone()),
            State::Pending(wakers) => {
                wakers.push(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl<T> State<T>
where
    T: Clone + Send + Sync,
{
    /// finish returns a list of Wakers to be awoken after the State is unlocked, lest any
    /// task be awoken and immediately contend with the lock.
    fn finish(&mut self, v: T) -> Vec<Waker> {
        // We do not want to run run drop() on the old Pending State.  We can safely extract its list
        // of Wakers though. An empty Vec is safe to forget as it points to nothing; Vec::new() is
        // `const`!
        let mut old_state = mem::ManuallyDrop::new(mem::replace(self, Self::Ready(v)));
        match &mut *old_state {
            Self::Pending(wakers) => mem::take(wakers),
            _ => unreachable!("A State should be finished only once"),
        }
    }
}

impl<T> Drop for State<T> {
    fn drop(&mut self) {
        // If all of the Tasks waiting on the value finish early or otherwise drop their handles,
        // we'll wake the FillFuture just so it can shut itself down and drop the Future that was
        // working towards generating the value.
        if let State::Pending(wakers) = self {
            for waker in mem::take(wakers) {
                waker.wake();
            }
        }
    }
}

struct FillFuture<T, F>
where
    T: Clone + Send + Sync,
    F: Future<Output = T> + Send + Sync,
{
    fut: F,
    state: Option<Weak<Mutex<State<T>>>>,
}

impl<T, F> Future for FillFuture<T, F>
where
    T: Clone + Send + Sync,
    F: Future<Output = T> + Send + Sync,
{
    type Output = Result<(), MeshError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // If there are no tasks waiting on this value, we'll just finish and drop `self.fut`
        // without completing it.
        let Some(arc) = self.state.as_ref().unwrap().upgrade() else {
            // Safety: nothing requires `self.state` to be Pin.
            unsafe { self.get_unchecked_mut() }.state = None;
            return Poll::Ready(Ok(()));
        };

        // Safety: `self.fut` can be Pin because `self` is.
        let poll = unsafe { self.as_mut().map_unchecked_mut(|s| &mut s.fut) }.poll(cx);
        let wake_self = cx.waker();
        let mut state = arc.lock().unwrap();
        match poll {
            Poll::Ready(v) => {
                let wakers = state.finish(v);
                drop(state);
                // Safety: nothing requires `self.state` to be Pin.
                unsafe { self.get_unchecked_mut() }.state = None;
                for waker in wakers.into_iter().filter(|w| !w.will_wake(wake_self)) {
                    waker.wake();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                // The value future is still pending. We'll add this Waker so that it may be called
                // if the state itself is dropped so that this Future may clean up.
                let State::Pending(wakers) = &mut *state else {
                    unreachable!("state should not be finished");
                };
                wakers.push(wake_self.clone());
                Poll::Pending
            }
        }
    }
}
