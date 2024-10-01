use alloc::string::String;
#[cfg(feature = "enclave")]
use core::sync::atomic::AtomicI64;
#[cfg(feature = "enclave")]
use core::sync::atomic::Ordering;
#[cfg(not(feature = "enclave"))]
use std::time::SystemTime;
#[cfg(not(feature = "enclave"))]
use std::time::UNIX_EPOCH;

#[cfg(feature = "enclave")]
static CURRENT_TIME: AtomicI64 = AtomicI64::new(0);

use chrono::TimeZone;
use chrono::Utc;

cfg_if::cfg_if! {
    if #[cfg(not(feature = "enclave"))] {
        pub fn get_current_time_ms() -> i64 {
            let now = SystemTime::now();
            let since_the_epoch = now.duration_since(UNIX_EPOCH).expect("could not get time");
            since_the_epoch.as_millis() as i64
        }
    } else if #[cfg(feature = "enclave")] {
        // Note on ordering: we are not particularly interested in catching concurrent threads
        // updating the time. However, it's difficult to predict exactly how things may evolve
        // around uses of the time, and if any decisions to change any other shared resources are
        // made based on one value of the time, it would be important that they all be seen in
        // order, so access to the time itself shall be done with sequential consistency.
        #[inline]
        pub fn set_current_time_ms(current_time: i64) {
            CURRENT_TIME.store(current_time, Ordering::SeqCst);
        }

        #[inline]
        pub fn get_current_time_ms() -> i64 {
            CURRENT_TIME.load(Ordering::SeqCst)
        }
    }
}

pub fn i64_to_iso_time_string(timestamp: i64) -> String {
    let timestamp = Utc.timestamp_millis_opt(timestamp);
    match timestamp {
        chrono::LocalResult::Single(dt) => dt.to_rfc3339(),
        _ => String::new(),
    }
}

pub fn i64_to_iso_time_string_check_zero(timestamp: i64) -> Option<String> {
    (timestamp != 0).then(|| match Utc.timestamp_millis_opt(timestamp) {
        chrono::LocalResult::Single(dt) => dt.to_rfc3339(),
        _ => String::new(),
    })
}
