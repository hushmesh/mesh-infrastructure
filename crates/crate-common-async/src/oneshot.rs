use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::sync::Weak;
use core::future::Future;
use core::pin::Pin;
use core::task::Context;
use core::task::Poll;
use core::task::Waker;

use crate::Mutex;

#[derive(Debug)]
pub struct SenderClosed;

pub struct Receiver<T>(Arc<Inner<T>>);
pub struct Sender<T>(Option<Weak<Inner<T>>>);

pub fn new<T>() -> (Receiver<T>, Sender<T>) {
    let inner = Arc::new(Mutex::new(State::Pending(None)));
    let weak = Arc::downgrade(&inner);
    (Receiver(inner), Sender(Some(weak)))
}

type Inner<T> = Mutex<State<T>>;

enum State<T> {
    // Pending starts with None, then holds the Waker provided in the last Receiver::poll().
    Pending(Option<Waker>),
    // Box<T> is used to avoid holding more memory than necessary for a prolonged case of waiting,
    // especially if either side gets dropped.
    Done(Option<Box<T>>),
}

impl<T> State<T> {
    fn finish(&mut self, v: Option<Box<T>>) {
        match core::mem::replace(self, State::Done(v)) {
            State::Pending(Some(waker)) => waker.wake(),
            State::Pending(None) => {}
            _ => unreachable!("A state should only be finished once"),
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        if let Some(arc) = self.0.take().and_then(|weak| weak.upgrade()) {
            arc.lock().unwrap().finish(None);
        }
    }
}

impl<T> Sender<T> {
    #[inline]
    pub fn send(mut self, v: T) {
        let weak = self.0.take().unwrap();
        if let Some(arc) = weak.upgrade() {
            arc.lock().unwrap().finish(Some(Box::new(v)));
        }
    }
}

impl<T> Future for Receiver<T> {
    type Output = Result<T, SenderClosed>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut *self.0.lock().unwrap() {
            State::Pending(waker) => {
                *waker = Some(cx.waker().clone());
                Poll::Pending
            }
            State::Done(done) => Poll::Ready(done.take().map(|b| *b).ok_or(SenderClosed)),
        }
    }
}

#[cfg(all(test, not(feature = "enclave")))]
mod tests {
    use super::*;

    #[test]
    fn test_send() {
        let (rx, tx) = new();

        let result = Arc::new(Mutex::new(None::<String>));
        let result_clone = result.clone();
        crate::start_one_task(async move {
            let v = rx.await.unwrap();
            *result_clone.lock().unwrap() = Some(v);
            Ok(())
        });

        assert!(matches!(
            &*tx.0.as_ref().unwrap().upgrade().unwrap().lock().unwrap(),
            State::Pending(Some(_))
        ));

        const STR: &str = "here's a string";

        tx.send(STR.into());

        crate::run_with_context(|| {
            crate::run_expired();
        });
        assert_eq!(
            Arc::try_unwrap(result)
                .unwrap()
                .into_inner()
                .unwrap()
                .unwrap(),
            STR
        );
    }

    #[test]
    fn test_drop_tx() {
        let (rx, tx) = new::<()>();

        let result = Arc::new(Mutex::new(None::<SenderClosed>));
        let result_clone = result.clone();
        crate::start_one_task(async move {
            let err = rx.await.unwrap_err();
            *result_clone.lock().unwrap() = Some(err);
            Ok(())
        });

        let weak = tx.0.as_ref().unwrap();
        {
            let arc = weak
                .upgrade()
                .expect("the running task should still hold an Arc");
            assert!(matches!(&*arc.lock().unwrap(), State::Pending(Some(_))));
        }
        assert_eq!((weak.strong_count(), weak.weak_count()), (1, 1));

        drop(tx);

        crate::run_with_context(|| {
            crate::run_expired();
        });
        assert!(Arc::try_unwrap(result)
            .expect("a reference to the oneshot inners still exists")
            .into_inner()
            .expect("nothing else should have a reference to result's Mutex")
            .is_some());
    }

    #[test]
    fn test_drop_rx() {
        let (_, tx) = new::<()>();
        let weak = tx.0.as_ref().unwrap();
        assert_eq!((weak.strong_count(), weak.weak_count()), (0, 0));
        tx.send(());
    }
}
