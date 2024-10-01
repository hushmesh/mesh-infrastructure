SHELL := /bin/bash


.DEFAULT_GOAL := all

BUILD_ENV ?= local

HUSHMESH_PREFIX := com.hushmesh.

APP_COMPILATION_DEPS := intermediates/build_data/$(HUSHMESH_PREFIX)appliction-build-data.json

RUST_SRC_DEPS := Cargo.toml $(shell find actors app* crates -name "*.rs" -or -name Cargo.toml 2>/dev/null)

.PHONY := all all-release all-debug all-test \
	hushmesh-crypto-app \
	wolfcrypt-app \
	clean clib-clean \


all: lib-release
test: lib-test

hushmesh-crypto-app: wolfcrypt-app
	make -C c-libraries/hushmesh-crypto/hushmesh-crypto-app install

wolfcrypt-app:
	make -C c-libraries/wolfssl lib-app

clean:
	rm -f bin/mesh-create-build-data
	rm -f intermediates/build_data/*.json
	cargo clean

clib-clean:
	rm -rf c-libraries/install
	make -C c-libraries/hushmesh-crypto/hushmesh-crypto-app clean
	make -C c-libraries/wolfssl clean

lib-release: $(APP_COMPILATION_DEPS) $(RUST_SRC_DEPS) hushmesh-crypto-app
	for dir in actors/*; do \
		set -e ; \
		cargo build --features enclave --release --manifest-path=$${dir}/Cargo.toml || exit 1; \
	done

lib-debug: $(APP_COMPILATION_DEPS) $(RUST_SRC_DEPS) hushmesh-crypto-app
	for dir in actors/*; do \
		set -e ; \
		cargo build --features enclave --manifest-path=$${dir}/Cargo.toml || exit 1; \
	done

lib-test: $(APP_COMPILATION_DEPS) $(RUST_SRC_DEPS) hushmesh-crypto-app
	cargo test

bin/mesh-create-build-data: $(RUST_SRC_DEPS) hushmesh-crypto-app
	cargo build --manifest-path app-create-build-data/Cargo.toml
	cp target/debug/mesh-create-build-data bin/mesh-create-build-data

intermediates/build_data/$(HUSHMESH_PREFIX)%-build-data.json: bin/mesh-create-build-data $(RUST_SRC_DEPS)
	BUILD_DATA_DIR=intermediates/build_data bin/mesh-create-build-data

doc:
	mkdir -p intermediates/build_data
	touch intermediates/build_data/com.hushmesh.agent-vdr-build-data.json
	RUSTDOCFLAGS="--enable-index-page -Z unstable-options" cargo +nightly doc --no-deps

.PRECIOUS: intermediates/build_data/$(HUSHMESH_PREFIX)%-build-data.json
