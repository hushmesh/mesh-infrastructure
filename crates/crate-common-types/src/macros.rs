pub use ::log;

#[macro_export]
macro_rules! log_error {
    ($fmt:literal, $err:expr) => {{
        let err = $err;
        if err != $crate::MeshError::NotFound {
            $crate::macros::log::error!($fmt, err);
        } else {
            $crate::macros::log::debug!($fmt, err);
        }
        err
    }};
    ($err:expr) => {
        $crate::log_error!("error: {}", $err);
    };
}

#[macro_export]
macro_rules! env_bool {
    ($name:literal) => {
        match ::core::env!($name).as_bytes() {
            b"0" => false,
            b"1" => true,
            _ => panic!(concat!($name, " must be \"0\" or \"1\"")),
        }
    };
}
