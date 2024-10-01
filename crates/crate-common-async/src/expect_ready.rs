use core::future::Future;
use core::future::IntoFuture;
use core::task::Context;
use core::task::Poll;

#[derive(Debug, PartialEq)]
pub struct FutureNotReady;

// Pins a value on the stack. This mimics tokio's `pin!`. When we upgrade rustc, we can use
// [`core::pin::pin!`], which works a little bit differently but provides the same effect.
macro_rules! pin {
    ($var:ident) => {
        let mut moved = $var;
        // Safety: we know we own `$var`, moved to `moved`, and it cannot be accessed except by its
        // new, pinned binding.
        let $var = unsafe { ::core::pin::Pin::new_unchecked(&mut moved) };
    };
}

pub fn expect_ready<T, F, IF>(fut: IF) -> Result<T, FutureNotReady>
where
    F: Future<Output = T>,
    IF: IntoFuture<IntoFuture = F>,
{
    let waker = fake_waker::new();
    let mut context = Context::from_waker(&waker);

    let fut = fut.into_future();
    pin!(fut);

    match fut.poll(&mut context) {
        Poll::Ready(v) => Ok(v),
        Poll::Pending => Err(FutureNotReady),
    }
}

mod fake_waker {
    use core::task::RawWaker;
    use core::task::RawWakerVTable;
    use core::task::Waker;

    use log::debug;

    pub(super) fn new() -> Waker {
        unsafe { Waker::from_raw(new_raw()) }
    }

    fn new_raw() -> RawWaker {
        RawWaker::new(core::ptr::null(), &FAKE_WAKER_VTABLE)
    }

    static FAKE_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);

    unsafe fn clone(_: *const ()) -> RawWaker {
        // It is unlikely, but not impossible, for a ready Future to clone a Waker, and for that
        // Waker to be awoken later.  But, it would be worth avoiding if possible, so there are
        // debug! logs.
        debug!("fake_waker::clone()");
        new_raw()
    }
    unsafe fn wake(_: *const ()) {
        debug!("fake_waker::wake()");
    }
    unsafe fn wake_by_ref(_: *const ()) {
        debug!("fake_waker::wake_by_ref()");
    }
    unsafe fn drop(_: *const ()) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_t() {
        let val = (12345u32, "str", None::<alloc::rc::Rc<()>>); // Eq- and Clone-able things...
        let from_fut = expect_ready(core::future::ready(val.clone())).unwrap();
        assert_eq!(val, from_fut);
    }

    #[test]
    fn not_ready() {
        assert_eq!(
            expect_ready(core::future::pending::<()>()),
            Err(FutureNotReady)
        );
    }
}
