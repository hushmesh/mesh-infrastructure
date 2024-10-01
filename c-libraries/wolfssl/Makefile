.PHONY: lib-app lib-enclave

APP_INSTALL_DIR = $(shell pwd)/../install/wolfssl-app
APP_LIB_TARGET = $(APP_INSTALL_DIR)/lib/libwolfssl.a
ENCLAVE_INSTALL_DIR = $(shell pwd)/../install/wolfssl-enclave
ENCLAVE_LIB_TARGET = $(ENCLAVE_INSTALL_DIR)/lib/libwolfssl.a

OQS_APP_INSTALL_DIR = $(shell pwd)/../install/oqs-app
OQS_APP_LIB_TARGET = $(OQS_APP_INSTALL_DIR)/lib/liboqs.a
OQS_ENCLAVE_INSTALL_DIR = $(shell pwd)/../install/oqs-enclave
OQS_ENCLAVE_LIB_TARGET = $(OQS_ENCLAVE_INSTALL_DIR)/lib/liboqs.a

wolfssl-5.7.0-upstream.tar.gz:
	rm -rf wolfssl-upstream
	git clone -b v5.7.0-stable --depth 1 https://github.com/wolfSSL/wolfssl.git wolfssl-upstream
	tar -cvzf wolfssl-5.7.0-upstream.tar.gz wolfssl-upstream
	rm -rf wolfssl-upstream

$(APP_LIB_TARGET): $(OQS_APP_LIB_TARGET) wolfssl-5.7.0-upstream.tar.gz
	mkdir -p $(APP_INSTALL_DIR)
	rm -rf wolfssl-app
	rm -rf wolfssl-upstream
	tar -xf wolfssl-5.7.0-upstream.tar.gz
	mv wolfssl-upstream wolfssl-app
	cd wolfssl-app && ./autogen.sh && ./configure --disable-shared --with-liboqs=$(OQS_APP_INSTALL_DIR) --enable-experimental --enable-static --enable-asn=template --enable-base64encode --enable-keygen --enable-certgen --enable-certreq --enable-certext --enable-hkdf --enable-eccencrypt --prefix=$(APP_INSTALL_DIR) --exec-prefix=$(APP_INSTALL_DIR) && make install

$(ENCLAVE_LIB_TARGET): $(OQS_ENCLAVE_LIB_TARGET) wolfssl-5.7.0-upstream.tar.gz
	mkdir -p $(ENCLAVE_INSTALL_DIR)/lib
	mkdir -p $(ENCLAVE_INSTALL_DIR)/include
	rm -rf wolfssl-enclave
	rm -rf wolfssl-upstream
	tar -xf wolfssl-5.7.0-upstream.tar.gz
	mv wolfssl-upstream wolfssl-enclave
	cd wolfssl-enclave && ./autogen.sh && ./configure --with-liboqs=$(OQS_ENCLAVE_INSTALL_DIR) --enable-experimental --disable-shared --enable-static --enable-asn=template --enable-base64encode --enable-keygen --enable-certgen --enable-certreq --enable-certext --enable-hkdf --enable-eccencrypt
	cp enclave_support/user_settings.h wolfssl-enclave/IDE/LINUX-SGX/.
	cp enclave_support/build.sh wolfssl-enclave/IDE/LINUX-SGX/.
	cp enclave_support/sgx_t_static.mk wolfssl-enclave/IDE/LINUX-SGX/.
	cd wolfssl-enclave && git apply ../enclave_support/sgx_sdk_mutex_and_gettime.patch
	cd wolfssl-enclave/IDE/LINUX-SGX && ./build.sh
	cp wolfssl-enclave/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a $(ENCLAVE_LIB_TARGET)
	cp -R wolfssl-enclave/wolfssl $(ENCLAVE_INSTALL_DIR)/include/.
	cp enclave_support/user_settings.h $(ENCLAVE_INSTALL_DIR)/include/.

liboqs-0.9.2-upstream.tar.gz:
	rm -rf liboqs-upstream
	git clone -b 0.9.2 --depth 1 https://github.com/open-quantum-safe/liboqs.git liboqs-upstream
	tar -cvzf liboqs-0.9.2-upstream.tar.gz liboqs-upstream
	rm -rf liboqs-upstream

$(OQS_APP_LIB_TARGET): liboqs-0.9.2-upstream.tar.gz
	rm -rf oqs-app
	rm -rf liboqs-upstream
	tar -xf liboqs-0.9.2-upstream.tar.gz
	mv liboqs-upstream oqs-app
	cp enclave_support/aes256_armv8.c oqs-app/src/common/aes/.
	cd oqs-app && mkdir build && cd build && cmake -GNinja .. -DOQS_ALGS_ENABLED="STD" -DOQS_BUILD_ONLY_LIB=on -DCMAKE_INSTALL_PREFIX=$(OQS_APP_INSTALL_DIR) -DOQS_USE_OPENSSL=OFF && ninja install

$(OQS_ENCLAVE_LIB_TARGET): liboqs-0.9.2-upstream.tar.gz
	rm -rf oqs-enclave
	rm -rf liboqs-upstream
	tar -xf liboqs-0.9.2-upstream.tar.gz
	mv liboqs-upstream oqs-enclave
	cp enclave_support/CMakeLists.txt oqs-enclave/src/common/.
	cd oqs-enclave && git apply ../enclave_support/sgx_oqs.patch
	cd oqs-enclave && mkdir build && cd build && cmake -GNinja .. -DOQS_ALGS_ENABLED="STD" -DOQS_BUILD_ONLY_LIB=on -DCMAKE_INSTALL_PREFIX=$(OQS_ENCLAVE_INSTALL_DIR) -DOQS_USE_OPENSSL=OFF && ninja install

lib-app: $(APP_LIB_TARGET)
lib-enclave: $(ENCLAVE_LIB_TARGET)

.DEFAULT_GOAL := lib-app

clean:
	rm -rf $(APP_INSTALL_DIR)
	rm -rf $(ENCLAVE_INSTALL_DIR)
	rm -rf $(OQS_APP_INSTALL_DIR)
	rm -rf $(OQS_ENCLAVE_INSTALL_DIR)
	rm -rf wolfssl-app
	rm -rf wolfssl-enclave
	rm -rf oqs-enclave
	rm -rf oqs-app
