SGX_SDK ?= /opt/intel/sgxsdk

CFLAGS = -fPIC -Wall -I../../install/wolfssl-app/include -I../../install/oqs-app/include
INSTALL_TARGET_DIR = ../../install/hushmesh-crypto-app/lib
BUILD_DIR=build

C_SRCS = $(shell find .. -maxdepth 1 -name "*.c" 2>/dev/null)
C_OBJS = $(patsubst ../%.c,$(BUILD_DIR)/%.o,$(C_SRCS))
LIB_OBJS = $(filter-out $(BUILD_DIR)/./test.o,$(C_OBJS))
TARGET = $(BUILD_DIR)/libhushmesh_crypto.a
INSTALL_TARGET = $(INSTALL_TARGET_DIR)/libhushmesh_crypto.a
$(BUILD_DIR)/%.o: ../%.c
	$(CC) -c $(CFLAGS) $< -o $@

$(TARGET): $(LIB_OBJS)
	rm -f $(TARGET)
	/usr/bin/ar q $(TARGET) $(LIB_OBJS)

clean:
	rm -f $(C_OBJS) $(TARGET) $(INSTALL_TARGET)

all: $(TARGET)

$(INSTALL_TARGET): $(TARGET)
	mkdir -p $(INSTALL_TARGET_DIR)
	cp $(TARGET) $(INSTALL_TARGET)

install: $(INSTALL_TARGET)
