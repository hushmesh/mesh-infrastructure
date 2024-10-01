fn main() {
    if cfg!(not(feature = "enclave")) {
        println!("cargo:rerun-if-changed=../../c-libraries/install/hushmesh-crypto-app/lib");
        println!("cargo:rustc-link-search=native=./c-libraries/install/hushmesh-crypto-app/lib");
        println!("cargo:rustc-link-lib=static=hushmesh_crypto");
        println!("cargo:rerun-if-changed=../../c-libraries/install/wolfssl-app/lib");
        println!("cargo:rustc-link-search=native=./c-libraries/install/wolfssl-app/lib");
        println!("cargo:rustc-link-lib=static=wolfssl");
        println!("cargo:rerun-if-changed=../../c-libraries/install/oqs-app/lib");
        println!("cargo:rustc-link-search=native=./c-libraries/install/oqs-app/lib");
        println!("cargo:rustc-link-lib=static=oqs");
    }
}
