fn main() {
    cc::Build::new().file("c/async_local_context.c").compile("async_local_context");
}
