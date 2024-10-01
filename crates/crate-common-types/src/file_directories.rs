use alloc::string::String;

#[cfg(not(feature = "enclave"))]
pub fn add_directory_to_shared_object(file_name: String) -> String {
    match std::env::var("ENCLAVE_DIR") {
        Ok(dir) => format!("{}/{}", dir, file_name),
        Err(_) => file_name,
    }
}

#[cfg(feature = "enclave")]
pub fn add_directory_to_shared_object(file_name: String) -> String {
    file_name
}
