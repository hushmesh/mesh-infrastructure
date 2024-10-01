void** local_context() {
	static __thread void *context;
	return &context;
}
